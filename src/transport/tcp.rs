use std::fmt::{Display, Formatter};
use prettytable::{format, table, row, cell};
use crate::util::*;

pub struct TcpSegment {
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgment_number: u32,
    data_offset: u8,
    checksum: u16,
}

impl TcpSegment {
    #[inline]
    pub fn source(&self) -> u16 {
        self.source_port
    }

    #[inline]
    pub fn destination(&self) -> u16 {
        self.destination_port
    }

    #[inline]
    pub fn sequence_number(&self) -> u32 {
        self.sequence_number
    }

    #[inline]
    pub fn acknowledgment_number(&self) -> u32 {
        self.acknowledgment_number
    }

    #[inline]
    pub fn data_offset(&self) -> u8 {
        self.data_offset
    }

    #[inline]
    pub fn checksum(&self) -> u16 {
        self.checksum
    }
}

impl From<&[u8]> for TcpSegment {
    fn from(data: &[u8]) -> Self {
        Self {
            source_port: tou16(&data[0..2]),
            destination_port: tou16(&data[2..4]),
            sequence_number: tou32(&data[4..8]),
            acknowledgment_number: tou32(&data[8..12]),
            data_offset: data[12] >> 4,
            checksum: tou16(&data[16..18]),
        }
    }
}

impl Display for TcpSegment {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut table = table!(
            ["source_port", self.source_port],
            ["destination_port", self.destination_port],
            ["sequence_number", self.sequence_number],
            ["acknowledgment_number", self.acknowledgment_number],
            ["data_offset", self.data_offset],
            ["checksum", self.checksum]
        );

        table.set_format(*format::consts::FORMAT_CLEAN);
        table.get_format().padding(5, 5);
        writeln!(f, "{}", table).unwrap();
        Ok(())
    }
}