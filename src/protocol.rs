const PAIR_REQUEST: u8 = b'\x00';
const NOTIF_CONN: u8 = b'\x01';

const DENY_PAIRING: u8 = b'\x02';
const ACCEPT_PAIRING: u8 = b'\x03';

const FLAG_INCLUDE_TITLE: u8 = 1;
const FLAG_INCLUDE_MESSAGE: u8 = 2;
const FLAG_INCLUDE_ICON: u8 = 4;

pub enum ConnType {
    PairRequest,
    NotifConn,
}

impl ConnType {
    pub fn from(b: u8) -> Option<Self> {
        match b {
            PAIR_REQUEST => Some(ConnType::PairRequest),
            NOTIF_CONN => Some(ConnType::NotifConn),
            _ => None,
        }
    }
}

pub enum PairingResponse {
    Accept,
    Deny,
}

impl PairingResponse {
    pub fn from(b: u8) -> Option<Self> {
        match b {
            DENY_PAIRING => Some(PairingResponse::Deny),
            ACCEPT_PAIRING => Some(PairingResponse::Accept),
            _ => None,
        }
    }
}

impl Into<u8> for PairingResponse {
    fn into(self) -> u8 {
        match self {
            PairingResponse::Deny => DENY_PAIRING,
            PairingResponse::Accept => ACCEPT_PAIRING,
        }
    }
}
