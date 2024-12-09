use tracing::info;

use crate::{arp_listener, tcp_listener};

use std::sync::mpsc;

pub fn start_tarpitting(passive_mode: bool, interface_name: &str) {
    let rx = arp_listener::start_arp_handling(interface_name, passive_mode);

    let (ip_sender, ip_receiver) = mpsc::channel();
    tcp_listener::start_tcp_tarpitting(interface_name, ip_receiver, passive_mode);

    for target_ip in rx {
        info!("Tarpitting IP: {}", target_ip);
        let _ = ip_sender.send(target_ip);
    }
}
