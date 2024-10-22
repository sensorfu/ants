 Use the official Rust image# Use the official Rust image
FROM rust:latestFROM rust:latest

WORKDIR /usr/src/hello_world

COPY . .

RUN apt-get update && \ apt-get install -y gcc libpcap-dev iproute2 && \ rm -rf /var/lib/apt/lists/* apt-get install -y gcc libpcap-dev iproute2 && \ rm -rf /var/lib/apt/lists/*# Build the application RUN cargo build --release
RUN cargo build --releaseRUN ls -la ./target/release/

RUN ls -la ./target/release/
EXPOSE 8080
CMD ["sh", "-c", "RUST_BACKTRACE=full ./target/release/ants"]


