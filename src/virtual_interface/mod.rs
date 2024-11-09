#![allow(dead_code)]
use std::io;
use std::process::Command;

pub fn create_macvlan_interface(physical_iface: &str, virtual_iface: &str, ip_address: &str) {
    // Create a MACVLAN interface using `ip link add`
    if let Err(e) = run_command(
        "ip",
        &[
            "link",
            "add",
            "link",
            physical_iface,
            virtual_iface,
            "type",
            "macvlan",
            "mode",
            "bridge",
        ],
    ) {
        eprintln!("Failed to create MACVLAN interface: {}", e);
        return;
    }

    // Bring up the virtual interface
    if let Err(e) = run_command("ip", &["link", "set", virtual_iface, "up"]) {
        eprintln!("Failed to bring up the virtual interface: {}", e);
        return;
    }

    // Assign an IP address to the new MACVLAN interface
    if let Err(e) = run_command("ip", &["addr", "add", ip_address, "dev", virtual_iface]) {
        eprintln!("Failed to assign IP address to MACVLAN interface: {}", e);
        return;
    }

    println!(
        "MACVLAN interface {} created on {} with IP address {}",
        virtual_iface, physical_iface, ip_address
    );
}

pub fn remove_macvlan_interface(virtual_iface: &str) {
    if let Err(e) = run_command("ip", &["link", "delete", virtual_iface]) {
        eprintln!(
            "Failed to remove MACVLAN interface {}: {}",
            virtual_iface, e
        );
        return;
    }

    println!("MACVLAN interface {} removed", virtual_iface);
}

/// Helper function to run shell commands
fn run_command(command: &str, args: &[&str]) -> io::Result<()> {
    let output = Command::new(command)
        .args(args)
        .output()
        .expect("failed to execute process");

    if !output.status.success() {
        println!(
            "Command `{}` failed with error: {}",
            command,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}
