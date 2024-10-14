#![allow(dead_code)]

use std::env;
mod arp_listener;
mod tcp_listener;
mod virtual_interface;

fn parse_arguments() -> bool {
    let args: Vec<String> = env::args().collect();
    args.contains(&"--passive".to_string())
}

fn main() {
    const INTERFACE_NAME: &str = "eth2";
    virtual_interface::remove_macvlan_interface("v192.168.68.42");

    let passive_mode = parse_arguments();

    let virtual_interface_name =
        arp_listener::listen_and_reply_unanswered_arps(INTERFACE_NAME, passive_mode);

    //tcp_listener::start_tcp_listener(VIRTUAL_INTERFACE_NAME);

    //virtual_interface::remove_macvlan_interface(&virtual_interface_name);
}
