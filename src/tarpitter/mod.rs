use crate::{arp_listener, tcp_listener, virtual_interface};
use std::{collections::HashMap, net::IpAddr, time::Instant};

pub fn start_tarpitting(passive_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    const INTERFACE_NAME: &str = "eth0";
    let mut arp_request_counts: HashMap<(IpAddr, IpAddr), (u32, Instant)> = HashMap::new();

    loop {
        match arp_listener::listen_and_reply_unanswered_arps(
            INTERFACE_NAME,
            &mut arp_request_counts,
            passive_mode,
        ) {
            Ok((virtual_interface_name, ip_address)) => {
                if let Err(e) =
                    tcp_listener::start_tcp_tarpitting(INTERFACE_NAME, ip_address, passive_mode)
                {
                    eprintln!("Error in TCP tarpitting: {}", e);
                }

                if let Err(e) = virtual_interface::remove_macvlan_interface(&virtual_interface_name)
                {
                    eprintln!(
                        "Failed to remove virtual interface {}: {}",
                        virtual_interface_name, e
                    );
                }
            }
            Err(e) => {
                eprintln!("Error in ARP handling: {}", e);
            }
        }
    }
}
