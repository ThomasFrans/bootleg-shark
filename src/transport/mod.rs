pub mod udp;
pub mod tcp;


pub type Protocol = u8;

pub const ICMP: Protocol = 1;
pub const IGMP: Protocol = 2;
pub const TCP: Protocol = 6;
pub const CHAOS: Protocol = 16;     // the protocol I use in my life...
pub const UDP: Protocol = 17;
pub const RDP: Protocol = 27;
pub const IPV6_ICMP: Protocol = 58;