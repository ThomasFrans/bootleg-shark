use std::fmt::{Display, Formatter};
use prettytable::{format, table, row, cell};
use crate::util::*;

pub struct ICMPSegment {
    icmp_type: u8,
    code: u8,
    checksum: u16,
    rest: u32,
}

impl From<&[u8]> for ICMPSegment {
    fn from(data: &[u8]) -> Self {
        Self {
            icmp_type: data[0],
            code: data[1],
            checksum: tou16(&data[2..4]),
            rest: tou32(&data[4..8])
        }
    }
}

impl Display for ICMPSegment {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let icmp_type = match self.icmp_type {
            ICMP_ECHO => "echo",
            ICMP_ECHO_REPLY => "echo reply",
            _ => "unidentified"
        };

        let mut table = table!(
            ["icmp_type", icmp_type],
            ["code", self.code],
            ["checksum", format!("{:X}", self.checksum)],
            ["rest", self.rest]
        );
        table.set_format(*format::consts::FORMAT_CLEAN);
        table.get_format().padding(5, 5);
        writeln!(f, "{}", table).unwrap();
        Ok(())
    }
}