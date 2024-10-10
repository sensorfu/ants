extern crate pnet_base;
extern crate pnet_datalink;
extern crate pnet_packet;

use pnet_base::MacAddr;
use pnet_datalink::Channel::Ethernet;
use pnet_packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet_packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet_packet::MutablePacket;
use pnet_packet::Packet;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

/// Function to listen to ARP traffic and return target and sender IP addresses on detection
pub fn listen_arp(interface_name: &str) -> (Ipv4Addr, Ipv4Addr) {
    let interfaces = pnet_datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect(&format!("No such interface: {}", interface_name));

    let (_, mut rx) = match pnet_datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Error creating channel: {}", e),
    };

    println!("Listening for ARP requests on {}", interface.name);

    // A map to track ARP request counts for each target IP address
    let mut arp_request_count: HashMap<IpAddr, (u32, Instant, IpAddr)> = HashMap::new();
    let request_threshold: u32 = 2;
    let request_timeout = Duration::from_secs(5);

    loop {
        match rx.next() {
            Ok(packet) => {
                let ethernet_packet = EthernetPacket::new(packet).unwrap();
                if let Some((target_ip, sender_ip)) = process_arp_packet(
                    &ethernet_packet,
                    &mut arp_request_count,
                    request_threshold,
                    request_timeout,
                ) {
                    return (target_ip, sender_ip);
                }
            }
            Err(e) => {
                println!("An error occurred while reading: {}", e);
            }
        }
    }
}

pub fn send_arp_reply(
    interface_name: &str,
    target_ip: Ipv4Addr,
    target_mac: MacAddr,
    sender_ip: Ipv4Addr,
    sender_mac: MacAddr,
) -> std::io::Result<()> {
    let interfaces = pnet_datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect(&format!("No such interface: {}", interface_name));

    let (mut tx, _) = match pnet_datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Error creating channel: {}", e),
    };

    let mut ethernet_buffer = [0u8; 42]; // 14 bytes for Ethernet + 28 bytes for ARP
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(target_mac);
    ethernet_packet.set_source(sender_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    create_arp_packet(
        &mut ethernet_packet,
        sender_mac,
        sender_ip,
        target_mac,
        target_ip,
    );

    let _ = tx
        .send_to(ethernet_packet.packet(), Some(interface))
        .expect("Failed to send ARP reply");

    println!(
        "Sent ARP reply: {} is at {:?} from {}",
        target_ip, sender_mac, sender_ip
    );
    Ok(())
}

fn create_arp_packet(
    ethernet_packet: &mut MutableEthernetPacket,
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
) {
    let mut arp_packet = MutableArpPacket::new(ethernet_packet.payload_mut()).unwrap();
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Reply);
    arp_packet.set_sender_hw_addr(sender_mac);
    arp_packet.set_sender_proto_addr(sender_ip);
    arp_packet.set_target_hw_addr(target_mac);
    arp_packet.set_target_proto_addr(target_ip);
}

fn track_arp_request(
    arp_request_count: &mut HashMap<IpAddr, (u32, Instant, IpAddr)>,
    target_ip: Ipv4Addr,
    request_threshold: u32,
    request_timeout: Duration,
    sender_ip: Ipv4Addr,
) -> Option<(Ipv4Addr, Ipv4Addr)> {
    let now = Instant::now();
    let entry =
        arp_request_count
            .entry(IpAddr::V4(target_ip))
            .or_insert((0, now, IpAddr::V4(sender_ip)));

    if now.duration_since(entry.1) > request_timeout {
        entry.0 = 0;
        entry.1 = now;
    }

    entry.0 += 1;

    if entry.0 >= request_threshold {
        println!(
            "Detected {} unanswered ARP requests for {}",
            request_threshold, target_ip
        );

        return Some((target_ip, sender_ip));
    }

    None
}

fn process_arp_packet(
    ethernet_packet: &EthernetPacket,
    arp_request_count: &mut HashMap<IpAddr, (u32, Instant, IpAddr)>,
    request_threshold: u32,
    request_timeout: Duration,
) -> Option<(Ipv4Addr, Ipv4Addr)> {
    if let Some(arp_packet) = ArpPacket::new(ethernet_packet.payload()) {
        let target_ip = Ipv4Addr::from(arp_packet.get_target_proto_addr());
        let sender_ip = Ipv4Addr::from(arp_packet.get_sender_proto_addr());
        let sender_hw = arp_packet.get_sender_hw_addr();

        match arp_packet.get_operation() {
            ArpOperations::Request => {
                println!("ARP Request: {} is asking for {}", sender_ip, target_ip);
                return track_arp_request(
                    arp_request_count,
                    target_ip,
                    request_threshold,
                    request_timeout,
                    sender_ip,
                );
            }
            ArpOperations::Reply => {
                println!("ARP Reply: {} is at {:?}", sender_ip, sender_hw);
                arp_request_count.remove(&IpAddr::V4(sender_ip));
            }
            _ => {}
        }
    }
    None
}
