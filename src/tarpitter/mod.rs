use crate::{arp_listener, tcp_listener};

pub fn start_tarpitting(passive_mode: bool) {
    const INTERFACE_NAME: &str = "wlo1";

    let rx = arp_listener::start_arp_handling(INTERFACE_NAME, passive_mode);

    for target_ip in rx {
        println!("Received target IP: {}", target_ip);

        let interface_name = INTERFACE_NAME.to_string();
        let ip_address = target_ip;

        std::thread::spawn(move || {
            tcp_listener::start_tcp_tarpitting(&interface_name, ip_address, passive_mode);
        });
    }
}
