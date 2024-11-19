mod arp_listener;
mod tarpitter;
mod tcp_listener;
mod virtual_interface;

use std::env;
use tokio;

fn parse_arguments() -> bool {
    let args: Vec<String> = env::args().collect();
    args.contains(&"--passive".to_string())
}
#[tokio::main]
async fn main() {
    let passive_mode = parse_arguments();

    tarpitter::start_tarpitting(passive_mode).await;
}
