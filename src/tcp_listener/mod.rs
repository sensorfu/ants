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
pub fn start_tcp_tarpitting(interface_name: &str, virtual_ip: Ipv4Addr, passive_mode: bool) {
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
        .immediate_mode(true)
        .open()
        .unwrap();

    println!(
        "Listening for incoming TCP SYN packets on interface {}...",
        interface_name
    );

    let timeout_duration = Duration::new(10, 0);
    let mut last_response_time = Instant::now();

    while let Ok(packet) = cap.next_packet() {
        let response_sent = handle_packet(packet.data, interface_name, virtual_ip, passive_mode);

        if response_sent {
            last_response_time = Instant::now()
        }

        if last_response_time.elapsed() >= timeout_duration {
            println!("No response sent in the last 10 seconds, exiting tcp_listener.");
            break;
        }
        thread::sleep(Duration::from_millis(300));
    }
}

fn send_syn_ack(
    interface_name: &str,
    dst_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    received_seq_num: u32,
) {
    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Could not find the specified interface");

    let mut eth_buffer = [0u8; 60]; // Ethernet header + IP + TCP

    let mut ethernet_packet = MutableEthernetPacket::new(&mut eth_buffer[..]).unwrap();
    ethernet_packet.set_source(interface.mac.unwrap());
    ethernet_packet.set_destination(dst_mac);
    ethernet_packet.set_ethertype(pnet::packet::ethernet::EtherType(0x0800));

    {
        let ipv4_buffer = &mut eth_buffer[14..34];
        let mut ipv4_packet = MutableIpv4Packet::new(ipv4_buffer).unwrap();

        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5);
        ipv4_packet.set_total_length((20 + 20) as u16);
        ipv4_packet.set_ttl(64);
        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ipv4_packet.set_source(src_ip);
        ipv4_packet.set_destination(dst_ip);
    }

    {
        let tcp_buffer = &mut eth_buffer[34..54];
        let mut tcp_packet = MutableTcpPacket::new(tcp_buffer).unwrap();

        tcp_packet.set_sequence(1);
        tcp_packet.set_acknowledgement(received_seq_num + 1);

        tcp_packet.set_source(src_port);
        tcp_packet.set_destination(dst_port);
        tcp_packet.set_data_offset(5);
        tcp_packet.set_flags(TcpFlags::SYN | TcpFlags::ACK);
        tcp_packet.set_window(1024);
        tcp_packet.set_checksum(0);

        let tcp_checksum = checksum(tcp_packet.packet(), 1);
        tcp_packet.set_checksum(tcp_checksum);
    }

    match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(mut tx, _)) => {
            let _ = tx.send_to(&eth_buffer, None).unwrap();
            println!("Sent SYN/ACK packet");
        }
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to send packet: {}", e),
    }
}

fn handle_packet(packet: &[u8], interface: &str, virtual_ip: Ipv4Addr, passive_mode: bool) -> bool {
    if packet.len() < 54 {
        return false;
    }

    let ethertype = u16::from_be_bytes([packet[12], packet[13]]);

    if ethertype != 0x0800 {
        return false;
    }

    let src_ip = Ipv4Addr::new(packet[26], packet[27], packet[28], packet[29]);
    let dst_ip = Ipv4Addr::new(packet[30], packet[31], packet[32], packet[33]);
    if dst_ip != virtual_ip {
        return false;
    }

    let src_mac = MacAddr::new(
        packet[6], packet[7], packet[8], packet[9], packet[10], packet[11],
    );

    let src_port = u16::from_be_bytes([packet[34], packet[35]]);
    let dst_port = u16::from_be_bytes([packet[36], packet[37]]);
    let tcp_flags = packet[47];
    let received_seq_num = u32::from_be_bytes([packet[38], packet[39], packet[40], packet[41]]);

    // Check if packet is a SYN packet
    if tcp_flags & 0x02 != 0 {
        println!(
            "Received SYN from {}:{} to {}:{}",
            src_ip, src_port, dst_ip, dst_port
        );

        if !passive_mode {
            send_syn_ack(
                interface,
                src_mac,
                dst_ip,
                src_ip,
                dst_port,
                src_port,
                received_seq_num,
            );
        }

        return true;
    }

    false
}
