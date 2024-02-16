use std::error::Error;
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::proxy::Proxy;
use crate::socks5::libs::io::connect_stream;
use crate::socks5::libs::statics::{
    AddressType, AuthMethods, Commands, FromToU8,
};

use super::libs::io::connect_remote;
use super::libs::statics::{Address, Reply};

pub fn check_valid_version(version: &u8) -> bool {
    // Check if version is 5
    return 0x05 == *version;
}

pub async fn start_proxy(
    proxy: Arc<Proxy>,
    server_addr: Option<String>,
    server_port: Option<i32>,
) -> Result<(), Box<dyn Error>> {
    let proxy_addr = String::from(format!(
        "{}:{}",
        server_addr.unwrap_or(String::from("0.0.0.0")),
        server_port.unwrap_or(1080)
    ));

    let listener =
        TcpListener::bind(proxy_addr.clone()).await?;

    println!("Proxys listening on: {}", proxy_addr);

    loop {
        let (socket, _) = listener.accept().await?;
        let copy = proxy.clone();
        tokio::spawn(async move {
            handle_connection(copy, socket).await;
        });
    }
}

async fn handle_connection(
    proxy: Arc<Proxy>,
    mut socket: TcpStream,
) {
    let mut buf: [u8; 258] = [0; 258];

    match socket.read(&mut buf).await {
        Ok(_n) => {
            if !check_valid_version(&buf[0]) {
                if let Err(_e) = socket
                    .write(&Reply::create_auth_reply(
                        Reply::GeneralFailure,
                    ))
                    .await
                {
                    panic!("Error sending response");
                }
            }

            let methods = &buf[2..(2 + buf[1] as usize)];

            // Proxy has two auth methods
            // With UsernamePassword and NoAuth
            // UsernamePassword is most priority
            if methods.contains(
                &AuthMethods::UsernamePassword.to_u8(),
            ) && proxy.check_valid_auth_method(
                &AuthMethods::UsernamePassword,
            ) {
                // Send UsernamePassword accept repl
                if let Err(_e) = socket
                    .write(&Reply::create_auth_reply(
                        Reply::Succeeded,
                    ))
                    .await
                {
                    panic!("Error sending response");
                }

                let mut buf: [u8; 258] = [0; 258];

                match socket.read(&mut buf).await {
                    Ok(n) => {
                        let username_length = buf[1];
                        let password_length = buf
                            [2 + username_length as usize];

                        let username = &buf[2..(2
                            + username_length as usize)];
                        let password = &buf[(3
                            + username_length as usize)
                            ..(3 + username_length
                                as usize
                                + password_length
                                    as usize)];

                        let username = String::from_utf8(
                            username.to_vec(),
                        )
                        .unwrap();
                        let password = String::from_utf8(
                            password.to_vec(),
                        )
                        .unwrap();

                        match proxy
                            .get_user(username.clone())
                        {
                            Some(_password) => {
                                if _password == password {
                                    if let Err(_e) = socket
                                        .write(&Reply::create_auth_reply(
                                            Reply::Succeeded,
                                        ))
                                        .await
                                    {
                                        panic!("Error sending response");
                                    }

                                    make_proxy(socket)
                                        .await;
                                } else {
                                    if let Err(_e) = socket
                                        .write(&Reply::create_auth_reply(
                                            Reply::GeneralFailure,
                                        ))
                                        .await
                                    {
                                        panic!("Error sending response");
                                    }
                                    return;
                                }
                            }
                            None => {
                                if let Err(_e) = socket
                                    .write(&Reply::create_auth_reply(
                                        Reply::GeneralFailure,
                                    ))
                                    .await
                                {
                                    panic!("Error sending response");
                                }
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        println!(
                            "Error reading from socket: {}",
                            e
                        );
                    }
                }
            } else if methods
                .contains(&AuthMethods::NoAuth.to_u8())
                && proxy.check_valid_auth_method(
                    &AuthMethods::NoAuth,
                )
            {
                if let Err(_e) = socket
                    .write(&Reply::create_auth_reply(
                        Reply::Succeeded,
                    ))
                    .await
                {
                    panic!("Error sending response");
                }

                make_proxy(socket).await;
            } else {
                if let Err(_e) = socket
                    .write(&Reply::create_auth_reply(
                        Reply::GeneralFailure,
                    ))
                    .await
                {
                    panic!("Error sending response");
                }
            }
        }
        Err(e) => {
            println!("Error reading from socket: {}", e);
        }
    }
}

/**
 *
 * Function to proxy
 *
 *
*/
async fn make_proxy(mut socket: TcpStream) {
    let mut request: [u8; 4] = [0; 4];

    // Read First 4 bytes
    match socket.read(&mut request).await {
        Ok(n) => {
            println!("Request : {:?}", request);

            if !check_valid_version(&request[0]) {
                println!("Not socks5 version");
                return;
            }

            let command = Commands::from_u8(request[1]);
            let address_type =
                AddressType::from_u8(request[3]);

            match command {
                Commands::Connect => {
                    println!("Connect command");
                    connection_handler(
                        socket,
                        address_type,
                    )
                    .await;
                }
                Commands::Bind => {
                    println!("Bind command not supported");
                    return;
                }
                Commands::UDPAssociate => {
                    println!("UDPAssociate command not supported");
                    return;
                }
            }

            return;
        }
        Err(e) => {
            panic!("Error reading from socket: {}", e);
        }
    }
}


async fn connection_handler(
    mut socket: TcpStream,
    address_type: AddressType,
) {
    match address_type {
        AddressType::IPv4 => {
            let mut address: [u8; 6] = [0; 6];
            match socket.read(&mut address).await {
                Ok(_n) => {
                    let port = u16::from_be_bytes([
                        address[4], address[5],
                    ]);

                    let remote = match connect_remote(
                        format!(
                            "{}.{}.{}.{}:{}",
                            address[0],
                            address[1],
                            address[2],
                            address[3],
                            port
                        ),
                    )
                    .await
                    {
                        Ok(remote) => remote,
                        Err(_err) => {
                            let reply =
                                Reply::create_connection_reply(
                                    Reply::ConnectionRefused,
                                    AddressType::IPv4,
                                    Address::IPv4([0, 0, 0, 0]),
                                    0,
                                );
                            if let Err(_e) =
                                socket.write(&reply).await
                            {
                                panic!("Error sending response");
                            }
                            panic!("Error connecting to remote");
                        }
                    };

                    if let Err(_e) = socket
                        .write(
                            &Reply::create_connection_reply(
                                Reply::Succeeded,
                                AddressType::IPv4,
                                Address::IPv4([
                                    address[0], address[1],
                                    address[2], address[3],
                                ]),
                                port,
                            ),
                        )
                        .await
                    {
                        panic!("Error sending response");
                    }

                    connect_stream(socket, remote).await;
                }
                Err(_e) => {
                    panic!(
                        "Error reading from socket: {}",
                        _e
                    );
                }
            }
        }
        AddressType::DomainName => {
            let mut domain_name_length: [u8; 1] = [0; 1];

            match socket.read(&mut domain_name_length).await
            {
                Ok(_n) => {
                    let domain_name_length =
                        domain_name_length[0];

                    let mut domain_name: Vec<u8> = vec![
                            0;
                            domain_name_length as usize
                        ];

                    match socket
                        .read(&mut domain_name)
                        .await
                    {
                        Ok(_n) => {
                            let domain_name =
                                String::from_utf8(
                                    domain_name,
                                )
                                .unwrap();
                            println!(
                                "Domain Name: {}",
                                domain_name
                            );

                            let mut port: [u8; 2] = [0; 2];

                            match socket
                                .read(&mut port)
                                .await
                            {
                                Ok(_n) => {
                                    let port =
                                        u16::from_be_bytes(
                                            [
                                                port[0],
                                                port[1],
                                            ],
                                        );
                                    println!(
                                        "Port: {}",
                                        port
                                    );

                                    let remote = match connect_remote(
                                        format!(
                                            "{}:{}",
                                            domain_name, port
                                        ),
                                    )
                                    .await
                                    {
                                        Ok(remote) => remote,
                                        Err(_err) => {
                                            let reply = Reply::create_connection_reply(Reply::ConnectionRefused, AddressType::IPv4, Address::IPv4([0, 0, 0, 0]), 0);
                                            if let Err(_e) = socket
                                                .write(&reply)
                                                .await
                                            {
                                                panic!("Error sending response");
                                            }
                                            panic!("Error connecting to remote");
                                        }
                                    };

                                    if let Err(_e) = socket.write(&Reply::create_connection_reply(Reply::Succeeded, AddressType::IPv4, Address::IPv4([0, 0, 0, 0]), 0)).await {
                                        panic!("Error sending response");
                                    }

                                    connect_stream(
                                        socket, remote,
                                    )
                                    .await;
                                }
                                Err(_e) => {
                                    panic!("Error reading from socket: {}", _e);
                                }
                            }
                        }
                        Err(_e) => {
                            panic!(
                                "Error reading from socket: {}",
                                _e
                            );
                        }
                    }
                }
                Err(_e) => {
                    panic!(
                        "Error reading from socket: {}",
                        _e
                    );
                }
            }
        }
        AddressType::IPv6 => {
            let mut address: [u8; 18] = [0; 18];

            match socket.read(&mut address).await {
                Ok(_n) => {
                    let ipv6_addr = Ipv6Addr::from([
                        address[0],
                        address[1],
                        address[2],
                        address[3],
                        address[4],
                        address[5],
                        address[6],
                        address[7],
                        address[8],
                        address[9],
                        address[10],
                        address[11],
                        address[12],
                        address[13],
                        address[14],
                        address[15],
                    ]);
                    let port = u16::from_be_bytes([
                        address[16],
                        address[17],
                    ]);

                    let remote = match connect_remote(
                        format!("[{}]:{}", ipv6_addr, port),
                    )
                    .await
                    {
                        Ok(remote) => remote,
                        Err(_err) => {
                            let reply =
                                Reply::create_connection_reply(
                                    Reply::ConnectionRefused,
                                    AddressType::IPv4,
                                    Address::IPv4([0, 0, 0, 0]),
                                    0,
                                );
                            if let Err(_e) =
                                socket.write(&reply).await
                            {
                                panic!("Error sending response");
                            }
                            panic!("Error connecting to remote");
                        }
                    };

                    if let Err(_e) = socket
                        .write(
                            &Reply::create_connection_reply(
                                Reply::Succeeded,
                                AddressType::IPv4,
                                Address::IPv4([
                                    address[0], address[1],
                                    address[2], address[3],
                                ]),
                                port,
                            ),
                        )
                        .await
                    {
                        panic!("Error sending response");
                    }

                    connect_stream(socket, remote).await;
                }
                Err(_e) => {
                    panic!(
                        "Error reading from socket: {}",
                        _e
                    );
                }
            }
        }
    }
}
