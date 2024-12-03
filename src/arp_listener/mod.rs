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

pub trait ArpPacketTrait {
    fn get_target_proto_addr(&self) -> Ipv4Addr;
    fn get_sender_proto_addr(&self) -> Ipv4Addr;
}

impl ArpPacketTrait for ArpPacket<'_> {
    fn get_target_proto_addr(&self) -> Ipv4Addr {
        self.get_target_proto_addr()
    }

    fn get_sender_proto_addr(&self) -> Ipv4Addr {
        self.get_sender_proto_addr()
    }
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
        target_ip: arp_request_info.sender_ip,
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
    arp_packet: &dyn ArpPacketTrait,
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
    }

    entry.0 += 1;
    entry.1 = now;

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

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::arp::{ArpHardwareType, ArpOperation, ArpOperations, MutableArpPacket};
    use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    const ETH_HEADER_LEN: usize = 14;
    const ARP_PACKET_LEN: usize = 28;
    const TOTAL_PACKET_LEN: usize = ETH_HEADER_LEN + ARP_PACKET_LEN;

    fn create_ethernet_with_arp(
        hw_type: ArpHardwareType,
        operation: ArpOperation,
        sender_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
    ) -> EthernetPacket<'static> {
        let mut packet_data = vec![0u8; TOTAL_PACKET_LEN];
        {
            let mut eth_packet = MutableEthernetPacket::new(&mut packet_data).unwrap();
            eth_packet.set_ethertype(EtherTypes::Arp);
            let mut arp_packet = MutableArpPacket::new(&mut packet_data[ETH_HEADER_LEN..]).unwrap();
            arp_packet.set_hardware_type(hw_type);
            arp_packet.set_protocol_type(EtherTypes::Ipv4);
            arp_packet.set_hw_addr_len(6);
            arp_packet.set_proto_addr_len(4);
            arp_packet.set_operation(operation);
            arp_packet.set_sender_proto_addr(sender_ip);
            arp_packet.set_target_proto_addr(target_ip);
        }
        EthernetPacket::owned(packet_data).unwrap()
    }

    #[test]
    fn test_process_arp_packet_request_below_threshold() {
        let ethernet_packet = create_ethernet_with_arp(
            ArpHardwareType(1),
            ArpOperations::Request,
            Ipv4Addr::new(192, 168, 0, 100),
            Ipv4Addr::new(192, 168, 0, 1),
        );

        let mut arp_request_count = HashMap::new();
        let request_threshold = 3;
        let request_timeout = Duration::from_secs(10);

        let result = process_arp_packet(
            &ethernet_packet,
            &mut arp_request_count,
            request_threshold,
            request_timeout,
        );

        assert!(result.is_none());
        assert_eq!(
            arp_request_count[&(
                IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 0, 100))
            )]
                .0,
            1
        );
    }

    #[test]
    fn test_process_arp_packet_request_exceed_threshold() {
        let ethernet_packet = create_ethernet_with_arp(
            ArpHardwareType(1),
            ArpOperations::Request,
            Ipv4Addr::new(192, 168, 0, 100),
            Ipv4Addr::new(192, 168, 0, 1),
        );

        let mut arp_request_count = HashMap::new();
        let request_threshold = 3;
        let request_timeout = Duration::from_secs(10);

        // Simulate previous requests
        arp_request_count.insert(
            (
                IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 0, 100)),
            ),
            (2, Instant::now()),
        );

        let result = process_arp_packet(
            &ethernet_packet,
            &mut arp_request_count,
            request_threshold,
            request_timeout,
        );

        assert!(result.is_some());
    }

    #[test]
    fn test_process_arp_packet_reply() {
        let ethernet_packet = create_ethernet_with_arp(
            ArpHardwareType(1),
            ArpOperations::Reply,
            Ipv4Addr::new(192, 168, 0, 100),
            Ipv4Addr::new(192, 168, 0, 1),
        );

        let mut arp_request_count = HashMap::new();
        let request_threshold = 3;
        let request_timeout = Duration::from_secs(10);

        // Simulate a tracked ARP request
        arp_request_count.insert(
            (
                IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 0, 100)),
            ),
            (2, Instant::now()),
        );

        let result = process_arp_packet(
            &ethernet_packet,
            &mut arp_request_count,
            request_threshold,
            request_timeout,
        );

        assert!(result.is_none());
        assert!(arp_request_count.is_empty());
    }

    #[test]
    fn test_process_arp_packet_invalid_hardware_type() {
        let ethernet_packet = create_ethernet_with_arp(
            ArpHardwareType(2), // Invalid hardware type
            ArpOperations::Request,
            Ipv4Addr::new(192, 168, 0, 100),
            Ipv4Addr::new(192, 168, 0, 1),
        );

        let mut arp_request_count = HashMap::new();
        let request_threshold = 3;
        let request_timeout = Duration::from_secs(10);

        let result = process_arp_packet(
            &ethernet_packet,
            &mut arp_request_count,
            request_threshold,
            request_timeout,
        );

        assert!(result.is_none());
        assert!(arp_request_count.is_empty());
    }

    // Mock implementation of the ArpPacketTrait for testing
    struct MockArpPacket {
        target_proto_addr: Ipv4Addr,
        sender_proto_addr: Ipv4Addr,
    }

    impl MockArpPacket {
        fn new(target_proto_addr: Ipv4Addr, sender_proto_addr: Ipv4Addr) -> Self {
            Self {
                target_proto_addr,
                sender_proto_addr,
            }
        }
    }

    impl ArpPacketTrait for MockArpPacket {
        fn get_target_proto_addr(&self) -> Ipv4Addr {
            self.target_proto_addr
        }

        fn get_sender_proto_addr(&self) -> Ipv4Addr {
            self.sender_proto_addr
        }
    }

    #[test]
    fn test_track_arp_request_no_threshold_reached() {
        let mock_arp_packet = MockArpPacket::new(
            Ipv4Addr::new(192, 168, 0, 1),
            Ipv4Addr::new(192, 168, 0, 100),
        );

        let mut arp_request_count: HashMap<(IpAddr, IpAddr), (u32, Instant)> = HashMap::new();
        let request_threshold = 3;
        let request_timeout = Duration::from_secs(10);

        let result = track_arp_request(
            &mock_arp_packet,
            &mut arp_request_count,
            request_threshold,
            request_timeout,
        );

        assert_eq!(result, false);
        assert_eq!(
            arp_request_count[&(
                IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 0, 100))
            )]
                .0,
            1
        );
    }

    #[test]
    fn test_track_arp_request_threshold_reached() {
        let mock_arp_packet = MockArpPacket::new(
            Ipv4Addr::new(192, 168, 0, 1),
            Ipv4Addr::new(192, 168, 0, 100),
        );

        let mut arp_request_count: HashMap<(IpAddr, IpAddr), (u32, Instant)> = HashMap::new();
        let request_threshold = 3;
        let request_timeout = Duration::from_secs(10);

        // Simulate previous requests
        arp_request_count.insert(
            (
                IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 0, 100)),
            ),
            (2, Instant::now()),
        );

        let result = track_arp_request(
            &mock_arp_packet,
            &mut arp_request_count,
            request_threshold,
            request_timeout,
        );

        assert_eq!(result, true);
        assert!(arp_request_count.is_empty());
    }

    #[test]
    fn test_track_arp_request_timeout_resets_count() {
        let mock_arp_packet = MockArpPacket::new(
            Ipv4Addr::new(192, 168, 0, 1),
            Ipv4Addr::new(192, 168, 0, 100),
        );

        let mut arp_request_count: HashMap<(IpAddr, IpAddr), (u32, Instant)> = HashMap::new();
        let request_threshold = 3;
        let request_timeout = Duration::from_secs(10);

        arp_request_count.insert(
            (
                IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 0, 100)),
            ),
            (2, Instant::now() - Duration::from_secs(20)),
        );

        let result = track_arp_request(
            &mock_arp_packet,
            &mut arp_request_count,
            request_threshold,
            request_timeout,
        );

        assert_eq!(result, false);
        assert_eq!(
            arp_request_count[&(
                IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 0, 100))
            )]
                .0,
            1
        );
    }
}
