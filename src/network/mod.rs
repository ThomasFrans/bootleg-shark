pub mod ipv6;
pub mod ipv4;
pub mod icmp;
pub mod arp;


pub type EthernetType = u16;

pub const IPV4: EthernetType = 0x0800;
pub const WOL: EthernetType = 0x0842;
pub const RARP: EthernetType = 0x8035;
pub const ARP: EthernetType = 0x0806;
pub const IPV6: EthernetType = 0x86DD;
pub const GOOSE: EthernetType = 0x88B8;      // you mess with the the honk, you get the bonk