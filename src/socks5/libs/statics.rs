
pub enum Methods{
    CONNECT = 0x01,
    BIND = 0x02,
    UDPAssociate = 0x03,
}

pub enum AddressType {
    IPv4 = 0x01,
    DomainName = 0x03,
    IPv6 = 0x04,
}

pub enum Address{
    IPv4([u8; 4]),
    IPv6([u8; 16]),
}

#[derive(PartialEq, Clone, Debug, Copy, Eq)]
pub enum AuthMethods {
    NoAuth = 0,
    GsSAPI = 1,
    UsernamePassword = 2,
    IANAAssigned = 3,
    Reserved = 4,
    NotAcceptable = 0xff,
}

#[derive(PartialEq, Clone, Debug)]
pub enum Command {
    Connect = 0x01,
    Bind = 0x02,
    UDPAssociate = 0x03,
}

pub enum Reply {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TTLExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}


impl Reply {
    pub fn create_auth_reply( status: Reply) -> [u8; 2] {
        let mut reply: [u8; 2] = [0; 2];
        reply[0] = 5u8;
        reply[1] = status as u8;

        reply
    }

    pub fn create_connection_reply(status: Reply, address_type: AddressType, address: Address, port: u16) -> Vec<u8> {
        let mut reply: Vec<u8> = Vec::new();
        
        match address{
            Address::IPv4(_addr) =>{
                reply.push(5u8);
                reply.push(status as u8);
                reply.push(0u8);
                reply.push(address_type as u8);
                reply.extend(_addr);
                reply.extend(&port.to_be_bytes());

            },
            Address::IPv6(_addr) =>{
                reply.push(5u8);
                reply.push(status as u8);
                reply.push(0u8);
                reply.push(address_type as u8);
                reply.extend(_addr);
                reply.extend(&port.to_be_bytes());
            }
        }
        reply
    }


}

impl AuthMethods {
    pub fn to_u8(&self) -> u8 {
        return *self as u8;
    }

    pub fn from_u8(value: u8) -> AuthMethods {
        match value {
            0 => AuthMethods::NoAuth,
            1 => AuthMethods::GsSAPI,
            2 => AuthMethods::UsernamePassword,
            3 => AuthMethods::IANAAssigned,
            4 => AuthMethods::Reserved,
            0xff => AuthMethods::NotAcceptable,
            _ => AuthMethods::NotAcceptable,
        }
    }
}
