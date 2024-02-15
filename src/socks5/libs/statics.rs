pub enum AddressType {
    IPv4 = 0x01,
    DomainName = 0x03,
    IPv6 = 0x04,
}

#[derive(PartialEq,Clone,Debug, Copy, Eq, Hash, Ord, PartialOrd)]
pub enum AuthMethods {
    NoAuth = 0,
    GsSAPI = 1,
    UsernamePassword = 2,
    IANAAssigned = 3,
    Reserved = 4,
    NotAcceptable = 0xff,
}

#[derive(PartialEq,Clone,Debug)]
pub enum Command{
    Connect = 0x01,
    Bind = 0x02,
    UDPAssociate = 0x03,
}

pub enum Reply{
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
/* 
    impl  Reply{
        pub fn create_auth_reply(auth_method: &AuthMethods, status: Reply) -> Vec<u8> {
            let mut reply: Vec<u8> = Vec::new();
            reply.push(status);
            reply.push(auth_method.clone() as u8);

            reply
        }
    }
*/

impl  AuthMethods {
    
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



