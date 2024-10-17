use std::{collections::HashMap, net::IpAddr, time::Instant};

use crate::{arp_listener, tcp_listener, virtual_interface};

pub fn start_tarpitting(passive_mode: bool) {
    const INTERFACE_NAME: &str = "eth0";

    //virtual_interface::remove_macvlan_interface("v192.168.68.42");

    let mut arp_request_counts: HashMap<(IpAddr, IpAddr), (u32, Instant)> = HashMap::new();

    loop {
        //println!("{:?}", arp_request_counts);
        let (virtual_interface_name, ip_address) = arp_listener::listen_and_reply_unanswered_arps(
            INTERFACE_NAME,
            &mut arp_request_counts,
            passive_mode,
        );
        tcp_listener::start_tcp_listener(INTERFACE_NAME, ip_address);
        virtual_interface::remove_macvlan_interface(&virtual_interface_name);
    }
}
