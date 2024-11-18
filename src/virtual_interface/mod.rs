use std::io;
use std::process::Command;

pub fn create_macvlan_interface(
    physical_iface: &str,
    virtual_iface: &str,
    ip_address: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    run_command(
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
    )?;

    // Bring up the virtual interface
    run_command("ip", &["link", "set", virtual_iface, "up"])?;

    // Assign an IP address to the new MACVLAN interface
    run_command("ip", &["addr", "add", ip_address, "dev", virtual_iface])?;

    println!(
        "MACVLAN interface {} created on {} with IP address {}",
        virtual_iface, physical_iface, ip_address
    );

    Ok(())
}

pub fn remove_macvlan_interface(virtual_iface: &str) -> Result<(), Box<dyn std::error::Error>> {
    run_command("ip", &["link", "delete", virtual_iface])?;
    println!("MACVLAN interface {} removed", virtual_iface);
    Ok(())
}

fn run_command(command: &str, args: &[&str]) -> io::Result<()> {
    let output = Command::new(command).args(args).output()?;

    if !output.status.success() {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "Command `{}` failed with error: {}",
                command,
                String::from_utf8_lossy(&output.stderr)
            ),
        ))?;
    }
    Ok(())
}
