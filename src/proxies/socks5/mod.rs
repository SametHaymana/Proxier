mod constant;
mod models;

use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
};

use async_trait::async_trait;
use constant::SOCKET5_VERSION;
use models::{
    AuthMethods, AuthReply, AuthRequest, CommandType,
    Reply, ReplyType, Request,
};
use parking_lot::RwLock;
use tokio::net::{TcpListener, TcpStream};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    runtime::Runtime,
};
use tracing::{error, info, instrument};
use uuid::Uuid;

use crate::models::users::User;

use super::{
    common::{ProxyError, Result as ProxyResult},
    proxy_manager::ProxyEx,
};

pub struct Socks5Proxy {
    // Port
    port: u16,

    avaliable_auth_methods: RwLock<Vec<u8>>,

    avaliable_users: Arc<RwLock<HashSet<Arc<User>>>>,
}

#[async_trait]
impl ProxyEx for Socks5Proxy {
    async fn start(&self) -> Result<(), String> {
        let addrs = format!("0.0.0.0:{}", self.port);

        let listener = TcpListener::bind(&addrs)
            .await
            .map_err(|_e| _e.to_string())?;

        info!("Starting sock5 proxy on : {}", addrs);

        loop {
            let (socket, addr) = listener
                .accept()
                .await
                .map_err(|_e| _e.to_string())?;
            tokio::spawn(Self::handle_conn(socket, addr));
        }
    }

    async fn set_avaliable_auth_methods(
        &mut self,
        methods: Vec<u8>,
    ) {
        let mut vec = self.avaliable_auth_methods.write();
        *vec = methods;
    }

    async fn avaliable_auth_methods(&self) -> Vec<u8> {
        self.avaliable_auth_methods.read().clone()
    }

    async fn avaliable_users(
        &self,
    ) -> Arc<RwLock<HashSet<Arc<User>>>> {
        self.avaliable_users.clone()
    }

    async fn set_user(&mut self, user: Arc<User>) {
        let mut users = self.avaliable_users.write();
        users.insert(user.clone());
    }

    async fn remove_user(&mut self, user_id: &str) -> bool {
        let user_id = match Uuid::from_str(user_id) {
            Ok(id) => id,
            Err(_) => return false,
        };

        let user = {
            let users = self.avaliable_users.read();
            users
                .iter()
                .find(|user| user.user_id == user_id)
                .cloned()
        };

        if user.is_none() {
            return false;
        }

        let mut users = self.avaliable_users.write();
        users.remove(&user.unwrap());

        true
    }
}

impl Socks5Proxy {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            avaliable_auth_methods: RwLock::new(Vec::new()),
            avaliable_users: Arc::new(RwLock::new(
                HashSet::new(),
            )),
        }
    }

    /// Handles an incoming SOCKS5 connection, processes the initial authentication request, and sends a response.
    ///
    /// The SOCKS5 protocol specifies that the client will send an initial connection message with a maximum size of
    /// 258 bytes. This message includes the SOCKS version, the number of authentication methods, and a list of
    /// available authentication methods supported by the client.
    ///
    /// The server must select one of the provided methods or indicate that no acceptable methods are available.
    ///
    /// ### Request Message Structure (Client to Server)
    ///
    /// ```text
    ///     +----+----------+----------+
    ///     |VER | NMETHODS | METHODS  |
    ///     +----+----------+----------+
    ///     | 1  |    1     | 1 to 255 |
    ///     +----+----------+----------+
    /// ```
    ///
    /// - `VER` (1 byte): Version of the SOCKS protocol. Should be `5`.
    /// - `NMETHODS` (1 byte): Number of supported authentication methods listed in the `METHODS` field.
    /// - `METHODS` (1-255 bytes): List of authentication methods supported by the client.
    ///
    /// ### Response Message Structure (Server to Client)
    ///
    /// ```text
    ///     +----+--------+
    ///     |VER | METHOD |
    ///     +----+--------+
    ///     | 1  |   1    |
    ///     +----+--------+
    /// ```
    ///
    /// - `VER` (1 byte): Version of the SOCKS protocol. Should be `5`.
    /// - `METHOD` (1 byte): The chosen authentication method. If no acceptable method is found, `0xFF` is returned.
    ///
    /// ### Authentication Methods
    ///
    /// The client may propose multiple authentication methods. The server should choose one and respond accordingly:
    ///
    /// - `0x00`: No authentication required
    /// - `0x01`: GSSAPI
    /// - `0x02`: Username/password
    /// - `0x03` to `0x7F`: IANA-assigned methods
    /// - `0x80` to `0xFE`: Reserved for private methods
    /// - `0xFF`: No acceptable authentication methods found
    ///
    /// # Arguments
    ///
    /// - `socket`: The `TcpStream` representing the client connection.
    /// - `addr`: The `SocketAddr` of the client.
    ///
    async fn handle_conn(
        mut socket: TcpStream,
        addr: SocketAddr,
    ) -> ProxyResult<()> {
        let mut buf: [u8; 258] = [0; 258];

        Self::read_message(&mut socket, &mut buf).await;

        let auth_request = AuthRequest::from_bytes(&buf);

        if let Err(_e) = auth_request {
            error!(
                "Error while parsing auth request: {}",
                _e
            );
            Self::close_socket(&mut socket).await;
            return Ok(());
        }

        // Safe Unwrap
        let auth_request = auth_request.unwrap();

        // Proxy server must support GSPAPI auth
        // TODO
        /*if auth_request.methods.contains(&AuthMethods::GsSAPI.to_byte()){
        } else*/
        if auth_request.methods.contains(
            &AuthMethods::UsernamePassword.to_byte(),
        ) {
            let resp = AuthReply::new(
                SOCKET5_VERSION,
                AuthMethods::UsernamePassword,
            );
            Self::send_message(
                &mut socket,
                &resp.to_byte(),
            )
            .await;
            Self::read_message(&mut socket, &mut buf).await;

            let (username, password) =
                Self::parse_user_pass(&buf);

            // Check username And password access
            info!(
                "USERNAME: {}, PASS: {}",
                username, password
            );
        } else if auth_request
            .methods
            .contains(&AuthMethods::NoAuth.to_byte())
        {
            info!("NO AUTH");
        } else {
            Self::close_socket(&mut socket).await;
            return Ok(());
        }

        // Validate access to client
        let resp = AuthReply::new(
            SOCKET5_VERSION,
            ReplyType::Succeeded.to_byte(),
        );

        Self::send_message(&mut socket, &resp.to_byte())
            .await;

        Self::command_handler(&mut socket).await;

        Ok(())
    }

    async fn command_handler(socket: &mut TcpStream) {
        // Buffer that min for read any request
        let mut buf: [u8; 262] = [0; 262];

        Self::read_message(socket, &mut buf).await;

        // Read request
        let req = Request::from_bytes(&buf);

        if let Err(_e) = req {
            error!("Error while parsing request: {}", _e);
            Self::close_socket(socket).await;
            return;
        }

        // Safe Unwrap
        let req = req.unwrap();

        match req.cmd {
            CommandType::Connect => {
                // Replay for accepting
                let reply = Reply::new(
                    ReplyType::Succeeded,
                    req.atyp.clone(),
                    req.dst_addr.clone(),
                    req.dst_port,
                );

                Self::send_message(
                    socket,
                    &reply.to_bytes(),
                )
                .await;

                // Connect two stream
                Self::cmd_connect_handler(socket, req)
                    .await;
            }
            CommandType::Bind => {
                Self::cmd_bind_handler(socket, req).await;
            }
            CommandType::UdpAssociate => {}
        }
    }

    // CMD connection handler
    async fn cmd_connect_handler(
        socket: &mut TcpStream,
        req: Request,
    ) {
        let Some(adrs) = req.dst_socket_addr else {
            Self::close_socket(socket).await;
            return;
        };

        let Ok(remote_socket) =
            TcpStream::connect(adrs).await
        else {
            // TODO
            // Return error message
            return;
        };

        let (mut src_read, mut src_write) =
            io::split(socket);
        let (mut dest_read, mut dest_write) =
            io::split(remote_socket);

        let copy_to_destination = async {
            io::copy(&mut src_read, &mut dest_write).await
        };

        let copy_to_source = async {
            io::copy(&mut dest_read, &mut src_write).await
        };

        let result = tokio::join!(
            copy_to_destination,
            copy_to_source
        );

        // Handle results if needed
        if let (Err(e), _) | (_, Err(e)) = result {
            error!("Error while proxying: {:?}", e);
        }
    }

    async fn cmd_bind_handler(
        socket: &mut TcpStream,
        req: Request,
    ) {
        let Some(bind_addrs) = req.dst_socket_addr else {
            // TODO
            // Handle
            return;
        };

        // Bind tha adress
        info!("BIND PORT ADDRES IS : {:?}", bind_addrs);

        let Ok(listener) =
            TcpListener::bind(bind_addrs).await
        else {
            // TODO
            // Handle
            return;
        };

        let Ok(local_addrs) = listener.local_addr() else {
            // TODO
            // Handle
            return;
        };

        // Return accept
        let reply = Reply::new(
            ReplyType::Succeeded,
            req.atyp.clone(),
            req.dst_addr.clone(),
            req.dst_port,
        );
        Self::send_message(socket, &reply.to_bytes()).await;

        // Accept connection
        let Ok((remote_socket, remote_addr)) =
            listener.accept().await
        else {
            // TODO
            // Handle
            return;
        };

        let addrs = match remote_addr.ip() {
            IpAddr::V4(ipv4) => ipv4.octets().to_vec(),
            IpAddr::V6(ipv6) => ipv6.octets().to_vec(),
        };

        let reply = Reply::new(
            ReplyType::Succeeded,
            req.atyp.clone(),
            addrs,
            remote_addr.port(),
        );
        Self::send_message(socket, &reply.to_bytes()).await;

        let (mut src_read, mut src_write) =
            io::split(socket);
        let (mut dest_read, mut dest_write) =
            io::split(remote_socket);

        let copy_to_destination = async {
            io::copy(&mut src_read, &mut dest_write).await
        };

        let copy_to_source = async {
            io::copy(&mut dest_read, &mut src_write).await
        };

        let result = tokio::join!(
            copy_to_destination,
            copy_to_source
        );

        // Handle results if needed
        if let (Err(e), _) | (_, Err(e)) = result {
            error!("Error while proxying: {:?}", e);
        }
    }

    pub async fn cmd_udp_associate(
        socket: &mut TcpStream,
        req: Request,
    ) {
        // TODO
    }

    fn parse_user_pass(buf: &[u8]) -> (String, String) {
        let username_length = buf[1] as usize;
        let password_length =
            buf[2 + username_length] as usize;

        // Correctly slice the buffer to extract username and password as Vec<u8>
        let username = buf[2..2 + username_length].to_vec();
        let password = buf[3 + username_length
            ..3 + username_length + password_length]
            .to_vec();

        let (username, password) = (
            String::from_utf8(username).unwrap_or_default(),
            String::from_utf8(password).unwrap_or_default(),
        );

        (username, password)
    }

    async fn read_message(
        socket: &mut TcpStream,
        buf: &mut [u8],
    ) -> usize {
        let bytes_read = match socket.read(buf).await {
            Ok(n) => n,
            Err(_e) => {
                error!("Socket reading error: {}", _e);
                Self::close_socket(socket).await;
                0
            }
        };
        bytes_read
    }

    async fn send_message(
        socket: &mut TcpStream,
        msg: &[u8],
    ) {
        if let Err(_e) = socket.write(msg).await {
            error!("Socket response writing error: {}", _e);
            return;
        }
    }

    async fn close_socket(socket: &mut TcpStream) {
        if let Err(_e) = socket.shutdown().await {
            error!("Error while shutdown socket: {}", _e);
        } else {
            info!("Socket closed succesfully");
        }
    }

    fn check_version_sock5(version: &u8) -> bool {
        return 0x05 == *version;
    }
}
