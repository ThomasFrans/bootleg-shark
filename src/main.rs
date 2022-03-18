use pnet::datalink::{self, MacAddr, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use std::fmt::{Display, Formatter};
use std::io::{stdout, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use prettytable::{table, row, cell, format};

const ARP: u16 = 0x0806;
const IPV4: u16 = 0x0800;
const IPV6: u16 = 0x86DD;
const UDP: u8 = 17;
const TCP: u8 = 6;
const ICMP: u8 = 1;
const ICMP_ECHO: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;

// Invoke as echo <interface name>
fn main() {
    let interface_names_match =
        |iface: &NetworkInterface| iface.name == "wlp0s20f3";

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    // Create a new channel, dealing with layer 2 packets
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e)
    };

    loop {
        match rx.next() {
            Ok(data) => {
                let frame = Frame::from(data);
                if frame.destination == MacAddr::new(0x94, 0xB8, 0x6D, 0xC4, 0xCD, 0x31) {
                    println!("----------------------------------------------------------------");
                    println!("LAYER 2: DATALINK - FRAME");
                    println!("{}", frame);
                    println!("LAYER 3: NETWORK - PACKET");
                    match frame.frame_type {
                        ARP => {
                            println!("{}", ARPPacket::from(frame.get_content()));
                        },
                        IPV4 => {
                            let packet = Ipv4Packet::from(frame.get_content());
                            println!("{}", packet);
                            println!("LAYER 4: SESSION - SEGMENT");
                            match packet.protocol {
                                TCP => {
                                    let segment = TcpSegment::from(packet.get_content());
                                    println!("{}", segment);
                                    if (segment.source_port == 80) | (segment.destination_port == 80) {
                                        println!("LAYER 5,6,7 - APPLICATION - DATA");
                                        stdout().write_all(&data[(14 + packet.ihl * 4 + segment.data_offset * 4) as usize..]).unwrap();
                                    }
                                },
                                UDP => {
                                    let segment = UDPSegment::from(&data[(14 + packet.ihl * 4) as usize..]);
                                    println!("{}", segment);
                                    println!("LAYER 5,6,7 - APPLICATION - DATA");
                                    stdout().write_all(&data[(14 + packet.ihl * 4 + 8) as usize..]).unwrap();
                                },
                                ICMP => {
                                    let segment = ICMPSegment::from(packet.get_content());
                                    println!("{}", segment);
                                    println!("LAYER 5,6,7 - APPLICATION - DATA");
                                    stdout().write_all(&packet.get_content()[40..]).unwrap();
                                    println!();
                                }
                                _ => println!("unidentified"),
                            }
                        },
                        IPV6 => {
                            println!("{}", Ipv6Packet::from(frame.get_content()));
                        },
                        _ => println!("unidentified")
                    };
                }
            }
            Err(_) => panic!()
        }
    }
}

#[derive(Debug)]
struct Frame<'a> {
    destination: MacAddr,
    source: MacAddr,
    frame_type: u16, 
    frame_data: &'a [u8]
}

impl<'a> Frame<'a> {
    fn from(data: &'a [u8]) -> Self {
        Self {
            destination: MacAddr::new(data[0], data[1], data[2], data[3], data[4], data[5]),
            source: MacAddr::new(data[6], data[7], data[8], data[9], data[10], data[11]),
            frame_type: (data[12] as u16) << 8 | data[13] as u16,
            frame_data: data
        }
    }

    fn get_content(&self) -> &[u8] {
        &self.frame_data[14..]
    }
}

impl<'a> Display for Frame<'a> {
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

#[derive(Debug)]
struct Ipv4Packet<'a> {
    version: u8,
    ihl: u8,
    tos: u8,
    total_length: u16,
    id: u16,
    flags: u8,
    offset: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    source_address: Ipv4Addr,
    destination_address: Ipv4Addr,
    packet_data: &'a [u8]
}

impl<'a> Ipv4Packet<'a> {
    fn from(data: &'a [u8]) -> Self {
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
            packet_data: data
        }
    }

    fn get_content(&self) -> &[u8] {
        &self.packet_data[(self.ihl*4) as usize..]
    }
}

impl<'a> Display for Ipv4Packet<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        #[allow(unused_assignments)]
        let mut version = "";
        if self.version == 4 {
            version = "ipv4";
        } else {
            version = "unidentified";
        }

        let protocol = match self.protocol {
            TCP => "tcp",
            UDP => "udp",
            ICMP => "icmp",
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

#[derive(Debug)]
struct ARPPacket {
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

#[inline]
fn tou16(data: &[u8]) -> u16 {
    (data[0] as u16) << 8 | (data[1] as u16)
}

#[inline]
fn tou32(data: &[u8]) -> u32 {
    (data[0] as u32) << 24 | (data[1] as u32) << 16 | (data[2] as u32) << 8 | (data[3] as u32)
}

#[inline]
fn tou64(data: &[u8]) -> u64 {
    (tou32(&data[0..4]) as u64) << 32 | (tou32(&data[4..8]) as u64)
}

#[inline]
fn tou128(data: &[u8]) -> u128 {
    (tou64(&data[0..8]) as u128) << 64 | (tou64(&data[8..16]) as u128)
}

impl ARPPacket {
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

#[derive(Debug)]
struct Ipv6Packet {
    version: u8,
    traffic_class: u8,
    flow_label: u32,
    payload_length: u16,
    next_header: u8,
    hop_limit: u8,
    source_address: Ipv6Addr,
    destination_address: Ipv6Addr,
}

impl Ipv6Packet {
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
        writeln!(f, "version: {}", self.version).unwrap();
        writeln!(f, "traffic_class: {}", self.traffic_class).unwrap();
        writeln!(f, "flow_label: {}", self.flow_label).unwrap();
        writeln!(f, "payload_length: {}", self.payload_length).unwrap();
        writeln!(f, "next_header: {}", self.next_header).unwrap();
        writeln!(f, "hop_limit: {}", self.hop_limit).unwrap();
        writeln!(f, "source_address: {}", self.source_address).unwrap();
        writeln!(f, "destination_address: {}", self.destination_address).unwrap();
        Ok(())
    }
}

struct TcpSegment {
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgment_number: u32,
    data_offset: u8,
    checksum: u16,
}

impl TcpSegment {
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

#[derive(Debug)]
struct UDPSegment {
    source_port: u16,
    destination_port: u16,
    length: u16,
    checksum: u16,
}

impl UDPSegment {
    fn from(data: &[u8]) -> Self {
        Self {
            source_port: tou16(&data[0..2]),
            destination_port: tou16(&data[2..4]),
            length: tou16(&data[4..6]),
            checksum: tou16(&data[6..8]),
        }
    }
}

impl Display for UDPSegment {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "source_port: {}", self.source_port).unwrap();
        writeln!(f, "destination_port: {}", self.destination_port).unwrap();
        writeln!(f, "length: {}", self.length).unwrap();
        writeln!(f, "checksum: {}", self.checksum).unwrap();
        Ok(())
    }
}

struct ICMPSegment {
    icmp_type: u8,
    code: u8,
    checksum: u16,
    rest: u32,
}

impl ICMPSegment {
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
