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
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

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

/// Creates thread to handle arp requests and replies
/// returns IPs which need to be tarpitted with mpsc channel
pub fn start_arp_handling(interface_name: &str, passive_mode: bool) -> mpsc::Receiver<Ipv4Addr> {
    let (tx, rx) = mpsc::channel();

    let interface_name = interface_name.to_string();

    thread::spawn(move || {
        let mut arp_request_counts: HashMap<(IpAddr, IpAddr), (u32, Instant)> = HashMap::new();
        let mut channel = open_channel(interface_name);
        loop {
            let arp_request_info = listen_arp(&mut arp_request_counts, &mut channel);
            send_arp_reply(&arp_request_info, passive_mode, &mut channel);

            if tx.send(arp_request_info.target_ip).is_err() {
                println!("Receiver dropped, exiting ARP handling thread.");
                break;
            }
        }
    });

    rx
}

fn listen_arp(
    arp_request_counts: &mut HashMap<(IpAddr, IpAddr), (u32, Instant)>,
    channel: &mut DataLinkChannel,
) -> ArpInfo {
    println!("Listening for ARP requests on {}", channel.interface);

    // A map to track ARP request counts for each target IP address
    let request_threshold: u32 = 2;
    let request_timeout = Duration::from_secs(5);

    loop {
        match channel.rx.next() {
            Ok(packet) => {
                let ethernet_packet = EthernetPacket::new(packet).unwrap();
                if let Some(arp_packet) = process_arp_packet(
                    &ethernet_packet,
                    arp_request_counts,
                    request_threshold,
                    request_timeout,
                ) {
                    let sender_ip: Ipv4Addr = arp_packet.get_sender_proto_addr();
                    let target_ip: Ipv4Addr = arp_packet.get_target_proto_addr();
                    let sender_mac: MacAddr = arp_packet.get_sender_hw_addr();
                    let target_mac: MacAddr = arp_packet.get_target_hw_addr();
                    return ArpInfo {
                        sender_ip,
                        target_ip,
                        sender_mac,
                        target_mac,
                    };
                }
            }
            Err(e) => {
                println!("An error occurred while reading: {}", e);
            }
        }
    }
}

fn send_arp_reply(arp_request_info: &ArpInfo, passive_mode: bool, channel: &mut DataLinkChannel) {
    let arp_reply_info = ArpInfo {
        sender_ip: arp_request_info.target_ip,
        target_ip: arp_request_info.target_ip,
        sender_mac: channel.mac_address,
        target_mac: arp_request_info.sender_mac,
    };

    let mut ethernet_buffer = [0u8; 42]; // 14 bytes for Ethernet + 28 bytes for ARP
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(arp_reply_info.target_mac);
    ethernet_packet.set_source(arp_reply_info.sender_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    create_arp_packet(&mut ethernet_packet, &arp_reply_info);

    if !passive_mode {
        let _ = channel
            .tx
            .send_to(ethernet_packet.packet(), Some(channel.interface.clone()))
            .expect("Failed to send ARP reply");
    }

    println!(
        "Sent ARP reply: {} is at {:?} from {}",
        arp_reply_info.target_ip, arp_reply_info.target_ip, arp_reply_info.sender_ip
    );
}

fn open_channel(interface_name: String) -> DataLinkChannel {
    let interface = get_interface(&interface_name);
    let (tx, rx) = match pnet_datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Error creating channel: {}", e),
    };

    let mac_address = interface.mac.unwrap_or_default();

    DataLinkChannel {
        tx,
        rx,
        interface,
        mac_address,
    }
}

fn get_interface(interface_name: &str) -> pnet_datalink::NetworkInterface {
    let interfaces = pnet_datalink::interfaces();
    let interface: pnet_datalink::NetworkInterface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .unwrap_or_else(|| panic!("No such interface: {}", interface_name));

    interface
}

fn create_arp_packet(ethernet_packet: &mut MutableEthernetPacket, arp_reply_info: &ArpInfo) {
    let mut arp_packet = MutableArpPacket::new(ethernet_packet.payload_mut()).unwrap();
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Reply);
    arp_packet.set_sender_hw_addr(arp_reply_info.sender_mac);
    arp_packet.set_sender_proto_addr(arp_reply_info.sender_ip);
    arp_packet.set_target_hw_addr(arp_reply_info.target_mac);
    arp_packet.set_target_proto_addr(arp_reply_info.target_ip);
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
        //Discard invalid packets
        if arp_packet.get_hardware_type() != pnet_packet::arp::ArpHardwareType(1) {
            return None;
        }
        let target_ip = arp_packet.get_target_proto_addr();
        let sender_ip = arp_packet.get_sender_proto_addr();
        let sender_hw = arp_packet.get_sender_hw_addr();

        //println!("{:?}", arp_packet);
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
