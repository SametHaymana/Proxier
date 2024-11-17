use std::convert::TryInto;
use std::net::ToSocketAddrs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use tracing::{debug, error, info};

#[derive(Debug)]
pub enum Commands {
    Connect,
    Bind,
    UdpAssociate,
}

impl Commands {
    pub fn to_byte(&self) -> u8 {
        match self {
            Commands::Connect => 0x01,
            Commands::Bind => 0x02,
            Commands::UdpAssociate => 0x03,
        }
    }

    pub fn from_byte(byte: u8) -> Result<Self, String> {
        match byte {
            0x01 => Ok(Commands::Connect),
            0x02 => Ok(Commands::Bind),
            0x03 => Ok(Commands::UdpAssociate),
            _ => Err(format!(
                "Invalid command byte: {}",
                byte
            )),
        }
    }
}

#[derive(Debug)]
pub enum AuthMethods {
    NoAuth,
    GsSAPI,
    UsernamePassword,
    IANAAssigned,
    Reserved,
    NotAcceptable,
}

impl AuthMethods {
    pub fn to_byte(&self) -> u8 {
        match self {
            AuthMethods::NoAuth => 0x00,
            AuthMethods::GsSAPI => 0x01,
            AuthMethods::UsernamePassword => 0x02,
            AuthMethods::IANAAssigned => 0x03,
            AuthMethods::Reserved => 0x80,
            AuthMethods::NotAcceptable => 0xff,
        }
    }

    pub fn from_byte(byte: u8) -> Result<Self, String> {
        match byte {
            0x00 => Ok(AuthMethods::NoAuth),
            0x01 => Ok(AuthMethods::GsSAPI),
            0x02 => Ok(AuthMethods::UsernamePassword),
            0x03 => Ok(AuthMethods::IANAAssigned),
            0x80 => Ok(AuthMethods::Reserved),
            0xff => Ok(AuthMethods::NotAcceptable),
            _ => Err(format!(
                "Invalid auth method byte: {}",
                byte
            )),
        }
    }
}

impl Into<u8> for AuthMethods {
    fn into(self) -> u8 {
        self.to_byte()
    }
}

impl Into<AuthMethods> for u8 {
    fn into(self) -> AuthMethods {
        AuthMethods::from_byte(self)
            .unwrap_or(AuthMethods::NotAcceptable)
    }
}

#[derive(Debug)]
pub enum ReplyType {
    Succeeded,
    GeneralFailure,
    ConnectionNotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
}

impl ReplyType {
    pub fn to_byte(&self) -> u8 {
        match self {
            ReplyType::Succeeded => 0x00,
            ReplyType::GeneralFailure => 0x01,
            ReplyType::ConnectionNotAllowed => 0x02,
            ReplyType::NetworkUnreachable => 0x03,
            ReplyType::HostUnreachable => 0x04,
            ReplyType::ConnectionRefused => 0x05,
            ReplyType::TtlExpired => 0x06,
            ReplyType::CommandNotSupported => 0x07,
            ReplyType::AddressTypeNotSupported => 0x08,
        }
    }

    pub fn from_byte(byte: u8) -> Result<Self, String> {
        match byte {
            0x00 => Ok(ReplyType::Succeeded),
            0x01 => Ok(ReplyType::GeneralFailure),
            0x02 => Ok(ReplyType::ConnectionNotAllowed),
            0x03 => Ok(ReplyType::NetworkUnreachable),
            0x04 => Ok(ReplyType::HostUnreachable),
            0x05 => Ok(ReplyType::ConnectionRefused),
            0x06 => Ok(ReplyType::TtlExpired),
            0x07 => Ok(ReplyType::CommandNotSupported),
            0x08 => Ok(ReplyType::AddressTypeNotSupported),
            _ => Err(format!(
                "Invalid reply type byte: {}",
                byte
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub enum AddressType {
    IPv4,
    DomainName,
    IPv6,
}

impl AddressType {
    pub fn to_byte(&self) -> u8 {
        match self {
            AddressType::IPv4 => 0x01,
            AddressType::DomainName => 0x03,
            AddressType::IPv6 => 0x04,
        }
    }

    pub fn from_byte(byte: u8) -> Result<Self, String> {
        match byte {
            0x01 => Ok(AddressType::IPv4),
            0x03 => Ok(AddressType::DomainName),
            0x04 => Ok(AddressType::IPv6),
            _ => Err(format!(
                "Invalid address type byte: {}",
                byte
            )),
        }
    }
}

#[derive(Debug)]
pub enum CommandType {
    Connect,
    Bind,
    UdpAssociate,
}

impl CommandType {
    pub fn to_byte(&self) -> u8 {
        match self {
            CommandType::Connect => 0x01,
            CommandType::Bind => 0x02,
            CommandType::UdpAssociate => 0x03,
        }
    }

    pub fn from_byte(byte: u8) -> Result<Self, String> {
        match byte {
            0x01 => Ok(CommandType::Connect),
            0x02 => Ok(CommandType::Bind),
            0x03 => Ok(CommandType::UdpAssociate),
            _ => Err(format!(
                "Invalid command type byte: {}",
                byte
            )),
        }
    }
}

/// +----+----------+----------+
/// |VER | NMETHODS | METHODS  |
/// +----+----------+----------+
/// | 1  |    1     | 1 to 255 |
/// +----+----------+----------+
#[derive(Debug)]
pub struct AuthRequest {
    pub version: u8,
    pub nmethods: u8,
    pub methods: Vec<u8>,
}

impl AuthRequest {
    pub fn new(methods: Vec<u8>) -> Self {
        Self {
            version: 0x05,
            nmethods: methods.len() as u8,
            methods,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.version);
        bytes.push(self.nmethods);
        bytes.extend_from_slice(&self.methods);
        bytes
    }

    pub fn from_bytes(
        bytes: &[u8],
    ) -> Result<Self, String> {
        if bytes.len() < 2 {
            return Err("Not enough bytes for AuthRequest"
                .to_string());
        }

        let version = bytes[0];
        if version != 0x05 {
            return Err(format!(
                "Unsupported version: {}",
                version
            ));
        }

        let nmethods = bytes[1];
        if bytes.len() < (2 + nmethods as usize) {
            return Err(
                "Not enough bytes for METHODS".to_string()
            );
        }

        let methods =
            bytes[2..(2 + nmethods as usize)].to_vec();
        Ok(Self {
            version,
            nmethods,
            methods,
        })
    }
}

/// +----+--------+
/// |VER | METHOD |
/// +----+--------+
/// | 1  |   1    |
/// +----+--------+
#[derive(Debug)]
pub struct AuthReply {
    version: u8,
    method: AuthMethods,
}

impl AuthReply {
    pub fn new(
        version: u8,
        method: impl Into<AuthMethods>,
    ) -> Self {
        Self {
            version,
            method: method.into(),
        }
    }

    pub fn from_bytes(
        bytes: &[u8],
    ) -> Result<Self, String> {
        // Check if there are enough bytes to read
        if bytes.len() < 2 {
            return Err("Not enough bytes for AuthReply"
                .to_string());
        }

        // Read fixed-size fields
        let version = bytes[0];
        if version != 0x05 {
            return Err(format!(
                "Unsupported version: {}",
                version
            ));
        }

        let method = AuthMethods::from_byte(bytes[1])?;
        Ok(Self { version, method })
    }

    pub fn to_byte(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.version);
        bytes.push(self.method.to_byte());
        bytes
    }
}

/// +----+-----+-------+------+----------+----------+
/// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
#[derive(Debug)]
pub struct Request {
    pub version: u8,
    pub cmd: CommandType,
    pub reserved: u8,
    pub atyp: AddressType,
    pub dst_addr: Vec<u8>,
    pub dst_port: u16,

    // dst_socket
    pub dst_socket_addr: Option<SocketAddr>,
}

impl Request {
    pub fn new(
        cmd: CommandType,
        atyp: AddressType,
        dst_addr: Vec<u8>,
        dst_port: u16,
    ) -> Self {
        Self {
            version: 0x05,
            cmd,
            reserved: 0x00,
            atyp,
            dst_addr,
            dst_port,
            dst_socket_addr: None,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.version);
        bytes.push(self.cmd.to_byte());
        bytes.push(self.reserved);
        bytes.push(self.atyp.to_byte());
        bytes.extend_from_slice(&self.dst_addr);
        bytes.extend_from_slice(
            &self.dst_port.to_be_bytes(),
        );
        bytes
    }

    pub fn from_bytes(
        bytes: &[u8],
    ) -> Result<Self, String> {
        info!("REQ ROW: {:?}", bytes);

        // Check if there are enough bytes to read
        if bytes.len() < 7 {
            return Err(
                "Not enough bytes for Request".to_string()
            );
        }

        // Read fixed-size fields
        let version = bytes[0];
        if version != 0x05 {
            return Err(format!(
                "Unsupported version: {}",
                version
            ));
        }

        let cmd = match bytes[1] {
            0x01 => CommandType::Connect,
            0x02 => CommandType::Bind,
            0x03 => CommandType::UdpAssociate,
            _ => {
                return Err(
                    "Invalid command type".to_string()
                )
            }
        };

        let reserved = bytes[2];
        if reserved != 0x00 {
            return Err(
                "Reserved field must be 0x00".to_string()
            );
        }

        let atyp = match bytes[3] {
            0x01 => AddressType::IPv4,
            0x03 => AddressType::DomainName,
            0x04 => AddressType::IPv6,
            _ => {
                return Err(
                    "Unsupported address type".to_string()
                )
            }
        };

        // Determine length of destination address
        let dst_addr_length = match atyp {
            AddressType::IPv4 => 4,
            AddressType::DomainName => {
                if bytes.len() < 5 {
                    return Err("Not enough bytes for domain length".to_string());
                }
                bytes[4] as usize + 1
            }
            AddressType::IPv6 => 16,
        };

        // Check if we have enough bytes for the destination address and port
        let required_length = 7 + dst_addr_length;
        if bytes.len() < required_length {
            return Err(format!(
                "Not enough bytes for destination address: required {}, found {}",
                required_length,
                bytes.len()
            ));
        }

        // Extract destination address and port
        let dst_addr =
            bytes[4..(4 + dst_addr_length)].to_vec();
        let dst_port = u16::from_be_bytes([
            bytes[4 + dst_addr_length],
            bytes[5 + dst_addr_length],
        ]);

        let socket_addr: Option<SocketAddr> = match atyp {
            AddressType::IPv4 => {
                if dst_addr.len() < 4 {
                    None
                } else {
                    let addrs = IpAddr::V4(Ipv4Addr::new(
                        dst_addr[0],
                        dst_addr[1],
                        dst_addr[2],
                        dst_addr[3],
                    ));
                    Some(SocketAddr::new(addrs, dst_port))
                }
            }
            AddressType::IPv6 => {
                if dst_addr.len() < 16 {
                    None
                } else {
                    let addrs =
                        IpAddr::V6(Ipv6Addr::from([
                            dst_addr[0],
                            dst_addr[1],
                            dst_addr[2],
                            dst_addr[3],
                            dst_addr[4],
                            dst_addr[5],
                            dst_addr[6],
                            dst_addr[7],
                            dst_addr[8],
                            dst_addr[9],
                            dst_addr[10],
                            dst_addr[11],
                            dst_addr[12],
                            dst_addr[13],
                            dst_addr[14],
                            dst_addr[15],
                        ]));
                    Some(SocketAddr::new(addrs, dst_port))
                }
            }
            AddressType::DomainName => {
                if let Ok(domain) =
                    String::from_utf8(dst_addr.to_vec())
                {
                    let addr = format!(
                        "{}:{}",
                        domain.trim(),
                        dst_port
                    );

                    info!("ADDRS : {}", &addr);
                    match addr.to_socket_addrs() {
                        Ok(mut addrs) => {
                            if let Some(socket_addr) =
                                addrs.next()
                            {
                                Some(socket_addr)
                            } else {
                                error!("No addresses found for domain: {}", addr);
                                None
                            }
                        }
                        Err(e) => {
                            error!("Failed to resolve socket address: {}", e);
                            None
                        }
                    }
                } else {
                    None
                }
            }
        };

        Ok(Self {
            version,
            cmd,
            reserved,
            atyp,
            dst_addr,
            dst_port,

            dst_socket_addr: socket_addr,
        })
    }
}

/// +----+-----+-------+------+----------+----------+
/// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+

#[derive(Debug)]
pub struct Reply {
    version: u8,
    reply: ReplyType,
    reserved: u8,
    atyp: AddressType,
    bnd_addr: Vec<u8>,
    bnd_port: u16,
}

impl Reply {
    pub fn new(
        reply: ReplyType,
        atyp: AddressType,
        bnd_addr: Vec<u8>,
        bnd_port: u16,
    ) -> Self {
        Self {
            version: 0x05,
            reply,
            reserved: 0x00,
            atyp,
            bnd_addr,
            bnd_port,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.version);
        bytes.push(self.reply.to_byte());
        bytes.push(self.reserved);
        bytes.push(self.atyp.to_byte());
        bytes.extend_from_slice(&self.bnd_addr);
        bytes.extend_from_slice(
            &self.bnd_port.to_be_bytes(),
        );
        bytes
    }
}

// UDP

/// +----+------+------+----------+----------+----------+
/// | RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
/// +----+------+------+----------+----------+----------+
/// |  2  |  1   |  1   | Variable |    2     | Variable |
/// +----+------+------+----------+----------+----------+
#[derive(Debug)]
pub struct UdpRequest {
    pub reserved: u16,
    pub frag: u8,
    pub atyp: AddressType,
    pub dst_addr: Vec<u8>,
    pub dst_port: u16,
    pub data: Vec<u8>, // UDP payload
}

impl UdpRequest {
    /// Constructs a new `UdpRequest`.
    pub fn new(
        reserved: u16,
        frag: u8,
        atyp: AddressType,
        dst_addr: Vec<u8>,
        dst_port: u16,
        data: Vec<u8>,
    ) -> Self {
        Self {
            reserved,
            frag,
            atyp,
            dst_addr,
            dst_port,
            data,
        }
    }

    /// Serializes the `UdpRequest` into a byte array.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            &self.reserved.to_be_bytes(),
        );
        bytes.push(self.frag);
        bytes.push(self.atyp.to_byte());
        bytes.extend_from_slice(&self.dst_addr);
        bytes.extend_from_slice(
            &self.dst_port.to_be_bytes(),
        );
        bytes.extend_from_slice(&self.data);
        bytes
    }

    /// Parses a `UdpRequest` from a byte array.
    pub fn from_bytes(
        bytes: &[u8],
    ) -> Result<Self, String> {
        if bytes.len() < 7 {
            return Err("Not enough bytes for UdpRequest"
                .to_string());
        }

        // Read fixed fields
        let reserved =
            u16::from_be_bytes([bytes[0], bytes[1]]);
        let frag = bytes[2];
        let atyp = AddressType::from_byte(bytes[3])
            .map_err(|_| {
                "Invalid address type".to_string()
            })?;

        // Determine destination address length
        let (dst_addr_length, addr_offset) = match atyp {
            AddressType::IPv4 => (4, 4),
            AddressType::DomainName => {
                (bytes[4] as usize + 1, 5)
            }
            AddressType::IPv6 => (16, 4),
        };

        if bytes.len() < addr_offset + dst_addr_length + 2 {
            return Err("Not enough bytes for destination address or port".to_string());
        }

        // Extract address and port
        let dst_addr = bytes
            [addr_offset..addr_offset + dst_addr_length]
            .to_vec();
        let dst_port = u16::from_be_bytes([
            bytes[addr_offset + dst_addr_length],
            bytes[addr_offset + dst_addr_length + 1],
        ]);

        // Extract data (UDP payload)
        let data_offset = addr_offset + dst_addr_length + 2;
        let data = bytes[data_offset..].to_vec();

        Ok(Self {
            reserved,
            frag,
            atyp,
            dst_addr,
            dst_port,
            data,
        })
    }
}

#[derive(Debug)]
pub struct UdpReply {
    pub reserved: u16,
    pub frag: u8,
    pub atyp: AddressType,
    pub dst_addr: Vec<u8>,
    pub dst_port: u16,
    pub data: Vec<u8>, // UDP payload
}

impl UdpReply {
    /// Constructs a new `UdpReply`.
    pub fn new(
        atyp: AddressType,
        dst_addr: Vec<u8>,
        dst_port: u16,
        data: Vec<u8>,
    ) -> Self {
        Self {
            reserved: 0x0000, // Always zero
            frag: 0x00, // Default fragment (no fragmentation)
            atyp,
            dst_addr,
            dst_port,
            data,
        }
    }

    /// Serializes the `UdpReply` into a byte array.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            &self.reserved.to_be_bytes(),
        );
        bytes.push(self.frag);
        bytes.push(self.atyp.to_byte());
        bytes.extend_from_slice(&self.dst_addr);
        bytes.extend_from_slice(
            &self.dst_port.to_be_bytes(),
        );
        bytes.extend_from_slice(&self.data);
        bytes
    }
}
