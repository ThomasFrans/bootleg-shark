use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use pnet::util::MacAddr;
use prettytable::{format, table, row, cell};
use crate::util::DataContainer;

#[derive(Debug)]
pub struct Frame {
    destination: MacAddr,
    source: MacAddr,
    frame_type: u16,
    frame_data: Vec<u8>
}

impl Frame {
    #[inline]
    pub fn destination(&self) -> &MacAddr {
        &self.destination
    }

    #[inline]
    pub fn source(&self) -> &MacAddr {
        &self.source
    }

    #[inline]
    pub fn frame_type(&self) -> u16 {
        self.frame_type
    }
}

impl From<&[u8]> for Frame {
    fn from(data: &[u8]) -> Self {
        Self {
            destination: MacAddr::new(data[0], data[1], data[2], data[3], data[4], data[5]),
            source: MacAddr::new(data[6], data[7], data[8], data[9], data[10], data[11]),
            frame_type: (data[12] as u16) << 8 | data[13] as u16,
            frame_data: Vec::from(&data[14..])
        }
    }
}

impl DataContainer for Frame {
    fn data(&self) -> &[u8] {
        self.frame_data.as_slice()
    }
}

impl Display for Frame {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let frame_type = match self.frame_type {
            IPV4 => "ipv4",
            ARP => "ARP",
            IPV6 => "ipv6",
            _ => "undefined"
        };

        let mut table = table!(
            ["destination", self.destination],
            ["source", self.source],
            ["frame_type", frame_type]
        );

        table.set_format(*format::consts::FORMAT_CLEAN);
        table.get_format().padding(5, 5);

        writeln!(f, "{}", table).unwrap();
        Ok(())
    }
}
