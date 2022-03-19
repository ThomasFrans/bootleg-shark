use std::fmt::{Display, Formatter};
use prettytable::{format, table, row, cell};
use crate::util::*;

#[derive(Debug)]
pub struct UDPSegment {
    source_port: u16,
    destination_port: u16,
    length: u16,
    checksum: u16,
    data: Vec<u8>
}

impl UDPSegment {
    #[inline]
    pub fn source(&self) -> u16 {
        self.source_port
    }
    
    #[inline]
    pub fn destination(&self) -> u16 {
        self.destination_port
    }
    
    #[inline]
    pub fn length(&self) -> u16 {
        self.length
    }
    
    #[inline]
    pub fn checksum(&self) -> u16 {
        self.checksum
    }
}

impl From<&[u8]> for UDPSegment {
    fn from(data: &[u8]) -> Self {
        Self {
            source_port: tou16(&data[0..2]),
            destination_port: tou16(&data[2..4]),
            length: tou16(&data[4..6]),
            checksum: tou16(&data[6..8]),
            data: Vec::from(&data[64..])
        }
    }
}

impl DataContainer for UDPSegment {
    fn data(&self) -> &[u8] {
        self.data.as_slice()
    }
}

impl Display for UDPSegment {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut table = table!(
            ["source_port", self.source_port],
            ["destination_port", self.destination_port],
            ["length", self.length],
            ["checksum", self.checksum]
        );

        table.set_format(*format::consts::FORMAT_CLEAN);
        table.get_format().padding(5, 5);

        writeln!(f, "{}", table);
        Ok(())
    }
}