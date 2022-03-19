use std::fmt::{Display, Formatter};
use crate::util::*;

#[derive(Debug)]
pub struct ARPPacket {
    hardware_type: u16,
    protocol_type: u16,
    hardware_length: u8,
    protocol_length: u8,
    operation: u16,
    sender_hardware_address: Vec<u8>,
    sender_protocol_address: Vec<u8>,
    receiver_hardware_address: Vec<u8>,
    receiver_protocol_address: Vec<u8>,
}

impl From<&[u8]> for ARPPacket {
    fn from(data: &[u8]) -> Self {
        Self {
            hardware_type: tou16(&data[0..2]),
            protocol_type: tou16(&data[2..4]),
            hardware_length: data[4],
            protocol_length: data[5],
            operation: tou16(&data[6..8]),
            sender_hardware_address: Vec::from(&data[8..8+data[4] as usize]),
            sender_protocol_address: Vec::from(&data[8+data[4] as usize..(8+data[4]+data[5]) as usize]),
            receiver_hardware_address: Vec::from(&data[(8+data[4]+data[5]) as usize..(8+data[4]*2+data[5]) as usize]),
            receiver_protocol_address: Vec::from(&data[(8+data[4]*2+data[5]) as usize..(8+data[4]*2+data[5]*2) as usize])
        }
    }
}

impl Display for ARPPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "hardware_type: ").unwrap();
        match self.hardware_type {
            1 => writeln!(f, "ethernet").unwrap(),
            6 => writeln!(f, "IEEE802 network").unwrap(),
            18 => writeln!(f, "fibre channel").unwrap(),
            _ => writeln!(f, "unidentified").unwrap(),
        };
        write!(f, "protocol_type: ").unwrap();
        match self.protocol_type {
            0x0800 => writeln!(f, "ipv4").unwrap(),
            0x0806 => writeln!(f, "ARP").unwrap(),
            0x86DD => writeln!(f, "ipv6").unwrap(),
            _ => writeln!(f, "unidentified").unwrap(),
        };
        writeln!(f, "hardware_length: {}", self.hardware_length).unwrap();
        writeln!(f, "protocol_length: {}", self.protocol_length).unwrap();
        write!(f, "operation: ").unwrap();
        match self.operation {
            1 => writeln!(f, "ARP request").unwrap(),
            2 => writeln!(f, "ARP reply").unwrap(),
            _ => writeln!(f, "unidentified").unwrap(),
        };
        writeln!(f, "sender_MAC: {:X?}", self.sender_hardware_address).unwrap();
        writeln!(f, "sender_protocol_address: {:?}", self.sender_protocol_address).unwrap();
        writeln!(f, "receiver_MAC: {:X?}", self.receiver_hardware_address).unwrap();
        writeln!(f, "receiver_protocol_address: {:?}", self.receiver_protocol_address).unwrap();
        Ok(())
    }
}