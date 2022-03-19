use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::net::Ipv4Addr;
use prettytable::{format, table, row, cell};
use crate::transport;
use crate::transport::Protocol;
use crate::util::DataContainer;

#[derive(Debug)]
pub struct Ipv4Packet {
    version: u8,
    ihl: u8,
    tos: u8,
    total_length: u16,
    id: u16,
    flags: u8,
    offset: u16,
    ttl: u8,
    protocol: Protocol,
    checksum: u16,
    source_address: Ipv4Addr,
    destination_address: Ipv4Addr,
    packet_data: Vec<u8>
}

impl From<&[u8]> for Ipv4Packet {
    fn from(data: &[u8]) -> Self {
        let header_length = ((data[0] & 0b00001111) * 4) as usize;
        println!("{}", data[9]);

        Self {
            version: data[0] >> 4,
            ihl: data[0] & 0b00001111,
            tos: data[1],
            total_length: (data[2] as u16) << 8 | data[3] as u16,
            id: (data[4] as u16) << 8 | data[5] as u16,
            flags: data[6] >> 5,
            offset: ((data[6] & 0b00011111) as u16) << 8 | data[7] as u16,
            ttl: data[8],
            protocol: data[9],
            checksum: (data[10] as u16) << 8 | data[11] as u16,
            source_address: Ipv4Addr::from([data[12], data[13], data[14], data[15]]),
            destination_address: Ipv4Addr::from([data[16], data[17], data[18], data[19]]),
            packet_data: Vec::from(&data[header_length..])
        }
    }
}

impl Ipv4Packet {
    #[inline]
    pub fn version(&self) -> u8 {
        self.version
    }

    #[inline]
    pub fn ihl(&self) -> u8 {
        self.ihl
    }

    #[inline]
    pub fn tos(&self) -> u8 {
        self.tos
    }

    #[inline]
    pub fn total_length(&self) -> u16 {
        self.total_length
    }

    #[inline]
    pub fn id(&self) -> u16 {
        self.id
    }

    #[inline]
    pub fn flags(&self) -> u8 {
        self.flags
    }

    #[inline]
    pub fn offset(&self) -> u16 {
        self.offset
    }

    #[inline]
    pub fn ttl(&self) -> u8 {
        self.ttl
    }

    #[inline]
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    #[inline]
    pub fn checksum(&self) -> u16 {
        self.checksum
    }

    #[inline]
    pub fn source(&self) -> Ipv4Addr {
        self.source_address
    }

    #[inline]
    pub fn destination(&self) -> Ipv4Addr {
        self.destination_address
    }
}

impl DataContainer for Ipv4Packet {
    fn data(&self) -> &[u8] {
        self.packet_data.as_slice()
    }
}

impl Display for Ipv4Packet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        #[allow(unused_assignments)]
            let mut version = "";
        if self.version == 4 {
            version = "ipv4";
        } else {
            version = "unidentified";
        }

        let protocol = match self.protocol {
            transport::TCP => "tcp",
            transport::UDP => "udp",
            transport::ICMP => "icmp",
            _ => "unidentified"
        };

        let mut table = table!(
            ["version", version],
            ["ihl", format!("{} words / {} bytes", self.ihl, self.ihl*4)],
            ["tos", self.tos],
            ["total_length", self.total_length],
            ["id", self.id],
            ["flags", self.flags],
            ["offset", self.offset],
            ["ttl", self.ttl],
            ["protocol", protocol],
            ["checksum", format!("{:X}", self.checksum)],
            ["source_address", self.source_address],
            ["destination_address", self.destination_address]
        );

        table.set_format(*format::consts::FORMAT_CLEAN);
        table.get_format().padding(5, 5);
        writeln!(f, "{}", table).unwrap();
        Ok(())
    }
}