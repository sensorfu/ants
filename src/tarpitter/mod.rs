use std::{collections::HashMap, net::IpAddr, time::Instant};
use tokio::task;
use tokio::time::{sleep, Duration};

use crate::{arp_listener, tcp_listener, virtual_interface};

pub async fn start_tarpitting(passive_mode: bool) {
    const INTERFACE_NAME: &str = "eth0";

    let mut arp_request_counts: HashMap<(IpAddr, IpAddr), (u32, Instant)> = HashMap::new();

    loop {
        let (virtual_interface_name, ip_address) = arp_listener::listen_and_reply_unanswered_arps(
            INTERFACE_NAME,
            &mut arp_request_counts,
            passive_mode,
        ).await;

        
        task::spawn(async move {
            print!("spawning new task!");
            tcp_listener::start_tcp_tarpitting(INTERFACE_NAME, ip_address, passive_mode);
            virtual_interface::remove_macvlan_interface(&virtual_interface_name);
        });

        //tcp_listener::start_tcp_tarpitting(INTERFACE_NAME, ip_address, passive_mode);
        //let virtual_interface_name = virtual_interface_name.to_string();
        //virtual_interface::remove_macvlan_interface(&virtual_interface_name);
    }
}