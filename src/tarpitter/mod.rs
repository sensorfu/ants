use std::{collections::HashMap, net::IpAddr, time::Instant};
use std::sync::Arc;
use tokio;
use tokio::sync::Mutex;
use tokio::task;
use crate::{arp_listener, tcp_listener, virtual_interface};

pub async fn start_tarpitting(passive_mode: bool) {
    const INTERFACE_NAME: &str = "eth0";

    let arp_request_counts: Arc<Mutex<HashMap<(IpAddr, IpAddr), (u32, Instant)>>> = Arc::new(Mutex::new(HashMap::new()));

    tokio::spawn(async move {
        let (virtual_interface_name, ip_address) = arp_listener::listen_and_reply_unanswered_arps(
            INTERFACE_NAME,
            arp_request_counts.clone(), 
            passive_mode,
        ).await;
    });

        //tcp_listener::start_tcp_tarpitting(INTERFACE_NAME, ip_address, passive_mode);

        //virtual_interface::remove_macvlan_interface(&virtual_interface_name);
}
