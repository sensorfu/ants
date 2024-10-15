use crate::{virtual_interface, arp_listener};

pub fn start_tarpitting(passive_mode: bool) {
    const INTERFACE_NAME: &str = "wlo1";
    virtual_interface::remove_macvlan_interface("v192.168.68.42");


    let virtual_interface_name =
        arp_listener::listen_and_reply_unanswered_arps(INTERFACE_NAME, passive_mode);

    //tcp_listener::start_tcp_listener(VIRTUAL_INTERFACE_NAME);

    //virtual_interface::remove_macvlan_interface(&virtual_interface_name);
}