use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::Packet;
use pnet::util::checksum;
use pnet_base::MacAddr;
use pnet_packet::ethernet::MutableEthernetPacket;
use std::net::Ipv4Addr;
use std::thread;
use std::time::{Duration, Instant};

// start listening to tcp and respond to TCP handshakes in the given interface
pub fn start_tcp_listener(interface_name: &str, virtual_ip: Ipv4Addr) {
    let device = pcap::Device::list()
        .unwrap()
        .into_iter()
        .find(|dev| dev.name == interface_name)
        .unwrap_or_else(|| {
            eprintln!("Could not find device {}", interface_name);
            std::process::exit(1);
        });

    let mut cap = pcap::Capture::from_device(device)
        .unwrap()
        .timeout(1000)
        .open()
        .unwrap();

    println!(
        "Listening for incoming TCP SYN packets on interface {}...",
        interface_name
    );

    while let Ok(packet) = cap.next_packet() {
        let response_sent = handle_packet(packet.data, interface_name, virtual_ip);
        if response_sent {
            return;
        }
        println!("Packet captured");
    }
}


fn send_syn_ack(
    interface_name: &str,
    dst_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    received_seq_num: u32, // The sequence number received in the SYN packet
) {
    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Could not find the specified interface");

    // Create a buffer for the packets
    let mut eth_buffer = [0u8; 60]; // Ethernet header + IP + TCP

    // Create a mutable Ethernet packet
    let mut ethernet_packet = MutableEthernetPacket::new(&mut eth_buffer[..]).unwrap();
    ethernet_packet.set_source(interface.mac.unwrap());
    ethernet_packet.set_destination(dst_mac); // Destination MAC address
    ethernet_packet.set_ethertype(pnet::packet::ethernet::EtherType(0x0800)); // EtherType for IPv4

    // Create mutable slices for IP and TCP headers
    {
        // Create mutable IPv4 packet
        let ipv4_buffer = &mut eth_buffer[14..34]; // IP header
        let mut ipv4_packet = MutableIpv4Packet::new(ipv4_buffer).unwrap();
        
        // Fill in the IPv4 header
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5); // IPv4 header length is 5 (20 bytes)
        ipv4_packet.set_total_length((20 + 20) as u16); // IPv4 + TCP header length
        ipv4_packet.set_ttl(64);
        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ipv4_packet.set_source(src_ip);
        ipv4_packet.set_destination(dst_ip);
    } // The mutable borrow of ipv4_buffer ends here

    // Now work with the TCP header
    {
        // Create mutable TCP packet
        let tcp_buffer = &mut eth_buffer[34..54]; // TCP header
        let mut tcp_packet = MutableTcpPacket::new(tcp_buffer).unwrap();
    

        // Set the sequence and acknowledgment numbers
        tcp_packet.set_sequence(1); // Set a random sequence number
        tcp_packet.set_acknowledgement(received_seq_num + 1); // Acknowledge the received SYN

        // Fill in the TCP header
        tcp_packet.set_source(src_port);
        tcp_packet.set_destination(dst_port);
        tcp_packet.set_data_offset(5); // TCP header length is 5 (20 bytes)
        tcp_packet.set_flags(TcpFlags::SYN | TcpFlags::ACK); // Set SYN and ACK flags
        tcp_packet.set_window(1024);
        tcp_packet.set_checksum(0); // Set checksum to 0 for calculation

        // Calculate checksums
        let tcp_checksum = checksum(tcp_packet.packet(), 1);
        tcp_packet.set_checksum(tcp_checksum);
    } // The mutable borrow of tcp_buffer ends here

    // Send the packet
    match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(mut tx, _)) => {
            let _ = tx.send_to(&eth_buffer, None).unwrap();
            println!("Sent SYN/ACK packet");
        }
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to send packet: {}", e),
    }
}

fn handle_packet(packet: &[u8], interface: &str, virtual_ip: Ipv4Addr) -> bool {
    println!("{}", packet.len());
    if packet.len() < 54 {
        return false; // Packet too short to be valid TCP/IP
    }

    let ethertype = u16::from_be_bytes([packet[12], packet[13]]);

    // Check if the packet is IPv4 (EtherType 0x0800)
    if ethertype != 0x0800 {
        match ethertype {
            0x0806 => println!("ARP packet"),
            0x86DD => println!("IPv6 packet"),
            0x8847 => println!("MPLS unicast packet"),
            0x8848 => println!("MPLS multicast packet"),
            _ => println!("Unknown packet type with EtherType: 0x{:04x}", ethertype),
        }
        return false;
    }

    // Continue processing the IPv4 packet
    println!("This is an IPv4 packet");

    // Parse IP header
    let src_ip = Ipv4Addr::new(packet[26], packet[27], packet[28], packet[29]);
    let dst_ip = Ipv4Addr::new(packet[30], packet[31], packet[32], packet[33]);
    if dst_ip != virtual_ip {
        println!("Wrong destination");
        return false;
    }

    // Get source MAC address
    let src_mac = MacAddr::new(
        packet[6],  // byte 1
        packet[7],  // byte 2
        packet[8],  // byte 3
        packet[9],  // byte 4
        packet[10], // byte 5
        packet[11], // byte 6
    );

    // Parse TCP header
    let src_port = u16::from_be_bytes([packet[34], packet[35]]);
    let dst_port = u16::from_be_bytes([packet[36], packet[37]]);
    let tcp_flags = packet[47];
    let received_seq_num = u32::from_be_bytes([packet[38], packet[39], packet[40], packet[41]]); // Extract the sequence number from the TCP header

    // Check if packet is a SYN packet
    if tcp_flags & 0x02 != 0 {
        println!(
            "Received SYN from {}:{} to {}:{}",
            src_ip, src_port, dst_ip, dst_port
        );

        // Send a SYN/ACK response
        send_syn_ack(interface, src_mac, dst_ip, src_ip, dst_port, src_port, received_seq_num);
        return true;
    }

    false
}
