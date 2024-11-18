mod arp_listener;
mod tarpitter;
mod tcp_listener;
mod virtual_interface;

use std::env;

fn parse_arguments() -> bool {
    let args: Vec<String> = env::args().collect();
    args.contains(&"--passive".to_string())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let passive_mode = parse_arguments();

    tarpitter::start_tarpitting(passive_mode)?;

    Ok(())
}
