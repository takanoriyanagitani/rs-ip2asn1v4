use std::io;

use der::{
    Encode, Sequence,
    asn1::{BitString, Uint},
};
use flagset::{FlagSet, flags};
use serde::{Deserialize, Serialize};

flags! {
    /// A tiny set of IP addresses in the 192.168.0.0/24 (Class C) range.
    #[repr(u8)]
    pub enum TinyIpSetsC0: u8 {
        /// 192.168.0.1
        V1 = 1 << 7,
        /// 192.168.0.2
        V2 = 1 << 6,
        /// 192.168.0.3
        V3 = 1 << 5,
        /// 192.168.0.4
        V4 = 1 << 4,
        /// 192.168.0.5
        V5 = 1 << 3,
        /// 192.168.0.6
        V6 = 1 << 2,
        /// 192.168.0.7
        V7 = 1 << 1,
    }
}

impl TinyIpSetsC0 {
    pub fn to_string(value: u8) -> String {
        let flags: FlagSet<TinyIpSetsC0> = FlagSet::new_truncated(value);
        format!("{:?}", flags)
    }

    pub fn raw2der_bytes(raw_value: u8) -> Result<Vec<u8>, io::Error> {
        let flags: FlagSet<TinyIpSetsC0> = FlagSet::new_truncated(raw_value);
        let bit_string = BitString::new(1, flags.bits().to_be_bytes()).map_err(io::Error::other)?;
        bit_string.to_der().map_err(io::Error::other)
    }
}

flags! {
    #[repr(u8)]
    pub enum IpV4Flag: u8 {
        /// Reserved, must be 0
        Reserved = 1 << 7,
        /// Don't Fragment
        Df = 1 << 6,
        /// More Fragments
        Mf = 1 << 5,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct IpV4 {
    pub ip: [u8; 4],
    pub fl: BitString,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IpV4Json {
    pub ip: String,
    pub fl: u8,
}

impl From<IpV4> for IpV4Json {
    fn from(val: IpV4) -> Self {
        IpV4Json {
            ip: val.ip.map(|v| v.to_string()).join("."),
            fl: val
                .fl
                .as_bytes()
                .map(|v| v.first().copied().unwrap_or(0))
                .unwrap_or(0),
        }
    }
}

impl TryFrom<IpV4Json> for IpV4 {
    type Error = ();

    fn try_from(value: IpV4Json) -> Result<Self, Self::Error> {
        let mut ip = [0u8; 4];
        for (i, v) in value.ip.split('.').enumerate() {
            if i > 3 {
                return Err(());
            }
            ip[i] = v.parse().map_err(|_| ())?;
        }

        let flags: FlagSet<IpV4Flag> = FlagSet::new_truncated(value.fl);
        let known_flags = IpV4Flag::Reserved | IpV4Flag::Df | IpV4Flag::Mf;
        if (flags & !known_flags) != FlagSet::empty() {
            return Err(());
        }

        let fl = BitString::new(5, [value.fl]).map_err(|_| ())?;
        Ok(IpV4 { ip, fl })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Asn1IpV4 {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    pub version: Uint,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT")]
    pub ip: IpV4,
}
