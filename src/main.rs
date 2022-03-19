mod util;
mod transport;
mod network;
mod datalink;
mod application;

use pnet::datalink::{MacAddr, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use std::fmt::{Display, Formatter};
use std::io::{stdout, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Deref;
use prettytable::{table, row, cell, format};
use crate::application::dns::DNSQuery;
use crate::datalink::ethernet::Frame;
use crate::network::arp::ARPPacket;
use crate::network::icmp::ICMPSegment;
use crate::network::ipv4::Ipv4Packet;
use crate::network::ipv6::Ipv6Packet;
use crate::transport::tcp::TcpSegment;
use crate::transport::udp::UDPSegment;
use crate::util::DataContainer;

// Invoke as echo <interface name>
fn main() {
    let interface_names_match =
        |iface: &NetworkInterface| iface.name == "wlp0s20f3";

    // Find the network interface with the provided name
    let interfaces = pnet::datalink::interfaces();
    let interface = interfaces.into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    // Create a new channel, dealing with layer 2 packets
    let (_, mut rx) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e)
    };

    loop {
        match rx.next() {
            Ok(data) => {
                let frame = Frame::from(data);
                if *frame.destination() == MacAddr::new(0x94, 0xB8, 0x6D, 0xC4, 0xCD, 0x31) {
                    println!("----------------------------------------------------------------");
                    println!("LAYER 2: DATALINK - FRAME");
                    println!("{}", frame);
                    println!("LAYER 3: NETWORK - PACKET");
                    match frame.frame_type() {
                        network::ARP => {
                            println!("{}", ARPPacket::from(frame.data()));
                        }
                        network::IPV4 => {
                            let packet = Ipv4Packet::from(frame.data());
                            println!("{}", packet);
                            println!("LAYER 4: SESSION - SEGMENT");
                            match packet.protocol() {
                                transport::TCP => {
                                    let segment = TcpSegment::from(packet.data());
                                    println!("{}", segment);
                                    println!("LAYER 5,6,7 - APPLICATION - DATA");
                                    if (segment.source() == 80) | (segment.destination() == 80) {
                                        stdout().write_all(&data[(14 + packet.ihl() * 4 + segment.data_offset() * 4) as usize..]).unwrap();
                                    } else if segment.source() == 53 {
                                        stdout().write_all(&data[(14 + packet.ihl() * 4 + segment.data_offset() * 4 + 16) as usize..]).unwrap();
                                    }
                                }
                                transport::UDP => {
                                    let segment = UDPSegment::from(&data[(14 + packet.ihl() * 4) as usize..]);
                                    println!("{}", segment);
                                    println!("LAYER 5,6,7 - APPLICATION - DATA");
                                    if segment.source() == 53 {
                                        println!("{}", DNSQuery::from(&data[(14 + packet.ihl() * 4 + 8) as usize..]));
                                    }
                                }
                                transport::ICMP => {
                                    let segment = ICMPSegment::from(packet.data());
                                    println!("{}", segment);
                                    println!("LAYER 5,6,7 - APPLICATION - DATA");
                                    stdout().write_all(&packet.data()[40..]).unwrap();
                                    println!();
                                }
                                _ => println!("unidentified")
                            }
                        }
                        network::IPV6 => {
                            println!("{}", Ipv6Packet::from(frame.data()));
                        }
                        _ => println!("unidentified")
                    };
                }
            }
            Err(_) => panic!()
        }
    }
}