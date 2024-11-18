extern crate pnet_base;
extern crate pnet_datalink;
extern crate pnet_packet;

use pnet_base::MacAddr;
use pnet_datalink::Channel::Ethernet;
use pnet_datalink::{DataLinkReceiver, DataLinkSender};
use pnet_packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet_packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet_packet::MutablePacket;
use pnet_packet::Packet;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use crate::virtual_interface;

struct ArpInfo {
    sender_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    sender_mac: MacAddr,
    target_mac: MacAddr,
}

struct DataLinkChannel {
    tx: Box<dyn DataLinkSender>,
    rx: Box<dyn DataLinkReceiver>,
    interface: pnet_datalink::NetworkInterface,
    mac_address: MacAddr,
}

/// Function to listen to ARP traffic and reply for unused IPs
/// In passive mode doesn't answer to requests, but only logs where it would reply
pub fn listen_and_reply_unanswered_arps(
    interface_name: &str,
    arp_request_counts: &mut HashMap<(IpAddr, IpAddr), (u32, Instant)>,
    passive_mode: bool,
) -> Result<(String, Ipv4Addr), Box<dyn std::error::Error>> {
    let arp_request_info = listen_arp(interface_name, arp_request_counts)?;
    send_arp_reply(interface_name, &arp_request_info, passive_mode)?;

    let virtual_iface_name = format!("v{}", arp_request_info.target_ip);
    println!("Create virtual interface {}", virtual_iface_name);

    virtual_interface::create_macvlan_interface(
        interface_name,
        &virtual_iface_name,
        &arp_request_info.target_ip.to_string(),
    )?;

    Ok((virtual_iface_name, arp_request_info.target_ip))
}

fn listen_arp(
    interface_name: &str,
    arp_request_counts: &mut HashMap<(IpAddr, IpAddr), (u32, Instant)>,
) -> Result<ArpInfo, Box<dyn std::error::Error>> {
    let mut channel = open_channel(interface_name)?;

    println!("Listening for ARP requests on {}", interface_name);

    let request_threshold: u32 = 2;
    let request_timeout = Duration::from_secs(5);

    loop {
        match channel.rx.next() {
            Ok(packet) => {
                let ethernet_packet =
                    EthernetPacket::new(packet).ok_or("Failed to parse Ethernet packet")?;

                if let Some(arp_packet) = process_arp_packet(
                    &ethernet_packet,
                    arp_request_counts,
                    request_threshold,
                    request_timeout,
                ) {
                    let sender_ip = arp_packet.get_sender_proto_addr();
                    let target_ip = arp_packet.get_target_proto_addr();
                    let sender_mac = arp_packet.get_sender_hw_addr();
                    let target_mac = arp_packet.get_target_hw_addr();

                    return Ok(ArpInfo {
                        sender_ip,
                        target_ip,
                        sender_mac,
                        target_mac,
                    });
                }
            }
            Err(e) => {
                return Err(format!("An error occurred while reading: {}", e).into());
            }
        }
    }
}

fn send_arp_reply(
    interface_name: &str,
    arp_request_info: &ArpInfo,
    passive_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut channel = open_channel(interface_name)?;

    let arp_reply_info = ArpInfo {
        sender_ip: arp_request_info.target_ip,
        target_ip: arp_request_info.target_ip,
        sender_mac: channel.mac_address,
        target_mac: channel.mac_address,
    };

    let mut ethernet_buffer = [0u8; 42]; // 14 bytes for Ethernet + 28 bytes for ARP
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer)
        .ok_or("Failed to create MutableEthernetPacket")?;

    ethernet_packet.set_destination(arp_reply_info.target_mac);
    ethernet_packet.set_source(arp_reply_info.sender_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    create_arp_packet(&mut ethernet_packet, &arp_reply_info)?;

    if !passive_mode {
        let result = channel
            .tx
            .send_to(ethernet_packet.packet(), Some(channel.interface));
        match result {
            Some(Ok(_)) => {}
            Some(Err(e)) => {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to send ARP reply: {}", e),
                )))
            }
            None => {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Cannot send ARP reply",
                )))
            }
        }
    }

    println!(
        "Sent ARP reply: {} is at {:?} from {}",
        arp_reply_info.target_ip, arp_reply_info.target_mac, arp_reply_info.sender_mac
    );

    Ok(())
}

fn open_channel(interface_name: &str) -> Result<DataLinkChannel, Box<dyn std::error::Error>> {
    let interface = get_interface(interface_name)?;
    let (tx, rx) = match pnet_datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Unhandled channel type",
            )))
        }
        Err(e) => return Err(Box::new(e)),
    };

    let mac_address = interface.mac.unwrap_or_default();

    Ok(DataLinkChannel {
        tx,
        rx,
        interface,
        mac_address,
    })
}

fn get_interface(
    interface_name: &str,
) -> Result<pnet_datalink::NetworkInterface, Box<dyn std::error::Error>> {
    let interfaces = pnet_datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .ok_or(Box::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("No such interface: {}", interface_name),
        )))?;

    Ok(interface)
}

fn create_arp_packet(
    ethernet_packet: &mut MutableEthernetPacket,
    arp_reply_info: &ArpInfo,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut arp_packet = MutableArpPacket::new(ethernet_packet.payload_mut())
        .ok_or("Failed to create MutableArpPacket")?;

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Reply);
    arp_packet.set_sender_hw_addr(arp_reply_info.sender_mac);
    arp_packet.set_sender_proto_addr(arp_reply_info.sender_ip);
    arp_packet.set_target_hw_addr(arp_reply_info.target_mac);
    arp_packet.set_target_proto_addr(arp_reply_info.target_ip);

    Ok(())
}

fn track_arp_request(
    arp_packet: &ArpPacket,
    arp_request_count: &mut HashMap<(IpAddr, IpAddr), (u32, Instant)>,
    request_threshold: u32,
    request_timeout: Duration,
) -> bool {
    let target_ip = arp_packet.get_target_proto_addr();
    let sender_ip = arp_packet.get_sender_proto_addr();
    let now = Instant::now();
    let entry = arp_request_count
        .entry((IpAddr::V4(target_ip), IpAddr::V4(sender_ip)))
        .or_insert((0, now));

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
        arp_request_count.remove(&(IpAddr::V4(target_ip), IpAddr::V4(sender_ip)));

        return true;
    }
    false
}

fn process_arp_packet<'a>(
    ethernet_packet: &'a EthernetPacket<'a>,
    arp_request_count: &'a mut HashMap<(IpAddr, IpAddr), (u32, Instant)>,
    request_threshold: u32,
    request_timeout: Duration,
) -> Option<ArpPacket<'a>> {
    if let Some(arp_packet) = ArpPacket::new(ethernet_packet.payload()) {
        // Discard invalid packets
        if arp_packet.get_hardware_type() != pnet_packet::arp::ArpHardwareType(1) {
            return None;
        }

        let target_ip = arp_packet.get_target_proto_addr();
        let sender_ip = arp_packet.get_sender_proto_addr();
        let sender_hw = arp_packet.get_sender_hw_addr();

        match arp_packet.get_operation() {
            ArpOperations::Request => {
                println!("ARP Request: {} is asking for {}", sender_ip, target_ip);
                let threshold_exceeded: bool = track_arp_request(
                    &arp_packet,
                    arp_request_count,
                    request_threshold,
                    request_timeout,
                );

                if threshold_exceeded {
                    return Some(arp_packet);
                }
            }
            ArpOperations::Reply => {
                println!("ARP Reply: {} is at {:?}", sender_ip, sender_hw);
                arp_request_count.remove(&(IpAddr::V4(target_ip), IpAddr::V4(sender_ip)));
            }
            _ => {}
        }
    }
    None
}
