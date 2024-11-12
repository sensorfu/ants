FROM rust:latest

WORKDIR /usr/src/ants

COPY . .

RUN apt-get update && \
    apt-get install -y gcc libpcap-dev iproute2 && \
    rm -rf /var/lib/apt/lists/*


RUN cargo build

RUN ls -la ./target/debug/


CMD ["sh", "-c", "RUST_BACKTRACE=full ./target/debug/ants"]


