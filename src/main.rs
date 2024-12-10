mod arp_listener;
mod tarpitter;
mod tcp_listener;

use std::env;
use std::process;
use tracing::info;
use tracing_subscriber::EnvFilter;

fn init_tracing(log_level: &str) {
    let filter = EnvFilter::try_new(log_level).unwrap_or_else(|_| {
        eprintln!("Invalid log level: {}. Defaulting to 'info'.", log_level);
        EnvFilter::new("info")
    });

    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn parse_arguments() -> (bool, String, String) {
    let args: Vec<String> = env::args().collect();

    let passive_mode = args.contains(&"--passive".to_string()) || args.contains(&"-p".to_string());

    let interface_index = args.iter().position(|arg| arg == "-i");
    let interface_name = match interface_index {
        Some(index) => {
            if let Some(name) = args.get(index + 1) {
                name.clone()
            } else {
                eprintln!("Error: No value provided for '-i' flag.");
                process::exit(1);
            }
        }
        None => {
            eprintln!("Error: The '-i <interface_name>' flag is mandatory.");
            process::exit(1);
        }
    };

    let log_level_index = args.iter().position(|arg| arg == "--log-level");
    let log_level = match log_level_index {
        Some(index) => {
            if let Some(level) = args.get(index + 1) {
                level.clone()
            } else {
                eprintln!("Error: No value provided for '--log-level' flag.");
                process::exit(1);
            }
        }
        None => "info".to_string(),
    };

    (passive_mode, interface_name, log_level)
}

fn main() {
    let (passive_mode, interface_name, log_level) = parse_arguments();

    init_tracing(&log_level);

    info!(
        "Starting tarpitting in {} mode",
        if passive_mode { "passive" } else { "active" }
    );
    info!("Interface: {}", interface_name);

    tarpitter::start_tarpitting(passive_mode, &interface_name);
}
