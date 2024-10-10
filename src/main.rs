mod arp_listener;
mod tcp_listener;
mod virtual_interface;

fn main() {
    const INTERFACE_NAME: &str = "eth0";
    const VIRTUAL_INTERFACE_NAME: &str = "macvlan0";
    virtual_interface::remove_macvlan_interface(VIRTUAL_INTERFACE_NAME);
    let (target_ip, sender_ip) = arp_listener::listen_arp(INTERFACE_NAME);
    println!(
        "Detected 2 unanswered ARP requests: target IP: {}, sender IP: {}",
        target_ip, sender_ip
    );
    virtual_interface::create_macvlan_interface(
        INTERFACE_NAME,
        VIRTUAL_INTERFACE_NAME,
        &target_ip.to_string(),
    );
}
