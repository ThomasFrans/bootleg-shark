use std::fmt::{Display, Formatter};
use std::net::Ipv6Addr;
use prettytable::{format, table, row, cell};
use crate::util::*;

#[derive(Debug)]
pub struct Ipv6Packet {
    version: u8,
    traffic_class: u8,
    flow_label: u32,
    payload_length: u16,
    next_header: u8,
    hop_limit: u8,
    source_address: Ipv6Addr,
    destination_address: Ipv6Addr,
}

impl From<&[u8]> for Ipv6Packet {
    fn from(data: &[u8]) -> Self {
        Self {
            version: data[0] >> 4,
            traffic_class: ((tou16(&data[0..2]) & 0b0000111111110000) >> 4) as u8,
            flow_label: tou32(&data[0..4]) & 0x000fffff,
            payload_length: tou16(&data[4..6]),
            next_header: data[6],
            hop_limit: data[7],
            source_address: Ipv6Addr::from(tou128(&data[8..24])),
            destination_address: Ipv6Addr::from(tou128(&data[24..40]))
        }
    }
}

impl Display for Ipv6Packet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut table = table!(
            ["version", self.version],
            ["traffic_class", self.traffic_class],
            ["flow_label", self.flow_label],
            ["payload_length", self.payload_length],
            ["next_header", self.next_header],
            ["hop_limit", self.hop_limit],
            ["source_address", self.source_address],
            ["destination_address", self.destination_address]
        );

        table.set_format(*format::consts::FORMAT_CLEAN);
        table.get_format().padding(5, 5);

        writeln!(f, "{}", table).unwrap();
        Ok(())
    }
}