use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::Packet;
use pnet::util::checksum;
use std::env;
use std::net::Ipv4Addr;

// start listening to tcp
pub fn start_tcp_listener() {
    // enable backtraces
    env::set_var("RUST_BACKTRACE", "1");

    // get the first available non-loopback interface
    let interface = match get_interface_name() {
        Some(iface) => iface,
        None => {
            eprintln!("Could not find a suitable network interface.");
            std::process::exit(1);
        }
    };

    // find the device corresponding to the selected interface
    let device = pcap::Device::list()
        .unwrap()
        .into_iter()
        .find(|dev| dev.name == interface)
        .unwrap_or_else(|| {
            eprintln!("Could not find device {}", interface);
            std::process::exit(1);
        });

    // open the capture on the found device
    let mut cap = pcap::Capture::from_device(device)
        .unwrap()
        .timeout(1000) // Timeout to avoid blocking indefinitely
        .open()
        .unwrap();

    println!(
        "Listening for incoming TCP SYN packets on interface {}...",
        interface
    );

    // capture packets in a loop
    while let Ok(packet) = cap.next_packet() {
        // pass the captured packet to the handle_packet function
        handle_packet(packet.data, &interface);
    }
}

/// get the interface
pub fn get_interface_name() -> Option<String> {
    let interfaces = datalink::interfaces();
    for iface in interfaces {
        if !iface.is_loopback() {
            return Some(iface.name.clone());
        }
    }
    None
}

/// send the SYN/ACK packet
fn send_syn_ack(
    interface_name: &str,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) {
    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Could not find the specified interface");

    // create a buffer for the packet
    let mut ipv4_buffer = [0u8; 20]; // IPv4 header length is 20 bytes
    let mut tcp_buffer = [0u8; 20]; // TCP header length is 20 bytes

    // create mutable IPv4 and TCP packets
    let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buffer[..]).unwrap();
    let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer[..]).unwrap();

    // fill in the IPv4 header
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5); // IPv4 header length is 5 (20 bytes)
    ipv4_packet.set_total_length((20 + 20) as u16); // IPv4 + TCP header length
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ipv4_packet.set_source(src_ip);
    ipv4_packet.set_destination(dst_ip);

    // fill in the TCP header
    tcp_packet.set_source(src_port);
    tcp_packet.set_destination(dst_port);
    tcp_packet.set_sequence(1);
    tcp_packet.set_acknowledgement(1);
    tcp_packet.set_data_offset(5); // TCP header length is 5 (20 bytes)
    tcp_packet.set_flags(TcpFlags::SYN | TcpFlags::ACK);
    tcp_packet.set_window(1024);
    tcp_packet.set_checksum(0); // set checksum to 0 for calculation

    // calculate checksums
    let tcp_checksum = checksum(tcp_packet.packet(), 1);
    tcp_packet.set_checksum(tcp_checksum);

    // build the packet by combining IP and TCP headers
    let mut final_packet = Vec::new();
    final_packet.extend_from_slice(ipv4_packet.to_immutable().packet());
    final_packet.extend_from_slice(tcp_packet.to_immutable().packet());

    // send the packet
    match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(mut tx, _)) => {
            let _ = tx.send_to(&final_packet, None).unwrap();
            println!("Sent SYN/ACK packet");
        }
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to send packet: {}", e),
    }
}

/// handle incoming packets and respond with SYN/ACK
pub fn handle_packet(packet: &[u8], interface: &str) {
    if packet.len() < 54 {
        return; // packet too short to be valid TCP/IP
    }

    // parse ethernet header (skip 14 bytes)
    let ethertype = u16::from_be_bytes([packet[12], packet[13]]);
    if ethertype != 0x0800 {
        return; // not an IPv4 packet
    }

    // parse IP header
    let src_ip = Ipv4Addr::new(packet[26], packet[27], packet[28], packet[29]);
    let dst_ip = Ipv4Addr::new(packet[30], packet[31], packet[32], packet[33]);

    // parse TCP header
    let src_port = u16::from_be_bytes([packet[34], packet[35]]);
    let dst_port = u16::from_be_bytes([packet[36], packet[37]]);
    let tcp_flags = packet[47];

    // check if packet is a SYN packet
    if tcp_flags & 0x02 != 0 {
        println!(
            "Received SYN from {}:{} to {}:{}",
            src_ip, src_port, dst_ip, dst_port
        );

        // send a SYN/ACK response
        send_syn_ack(interface, dst_ip, src_ip, dst_port, src_port);
    }
}
