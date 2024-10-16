use std::{collections::HashMap, net::IpAddr, time::Instant};

use crate::arp_listener;

pub fn start_tarpitting(passive_mode: bool) {
    const INTERFACE_NAME: &str = "eth0";

    //virtual_interface::remove_macvlan_interface("v192.168.68.42");

    let mut arp_request_counts: HashMap<(IpAddr, IpAddr), (u32, Instant)> = HashMap::new();

    loop {
        //println!("{:?}", arp_request_counts);
        let _virtual_interface_name = arp_listener::listen_and_reply_unanswered_arps(
            INTERFACE_NAME,
            &mut arp_request_counts,
            passive_mode,
        );
    }

    //tcp_listener::start_tcp_listener(VIRTUAL_INTERFACE_NAME);

    //virtual_interface::remove_macvlan_interface(&virtual_interface_name);
}
