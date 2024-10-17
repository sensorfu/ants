#![allow(dead_code)]

mod arp_listener;
mod tarpitter;
mod tcp_listener;
mod virtual_interface;

use std::{env, net::Ipv4Addr, str::FromStr};

use std::env;

fn parse_arguments() -> bool {
    let args: Vec<String> = env::args().collect();
    args.contains(&"--passive".to_string())
}

fn main() {
    let passive_mode = parse_arguments();

    tarpitter::start_tarpitting(passive_mode);
    //virtual_interface::remove_macvlan_interface("macvlan0");
    //irtual_interface::create_macvlan_interface("eth0", "macvlan0", "172.23.146.42");
    //let virtual_ip = Ipv4Addr::from_str("172.23.146.42").unwrap();
    //tcp_listener::start_tcp_listener("eth0", virtual_ip);
}
