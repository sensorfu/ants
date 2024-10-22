 Use the official Rust image# Use the official Rust image
FROM rust:latestFROM rust:latest

# Create a new directory for the app Create a new directory for the appWORKDIR /usr/src/hello_world
WORKDIR /usr/src/hello_world
# Copy the entire project into the Docker image Copy the entire project into the Docker imageCOPY . .
COPY . .
# Install build tools and the necessary libraries Install build tools and the necessary librariesRUN apt-get update && \
RUN apt-get update && \ apt-get install -y gcc libpcap-dev iproute2 && \ rm -rf /var/lib/apt/lists/* apt-get install -y gcc libpcap-dev iproute2 && \ rm -rf /var/lib/apt/lists/*# Build the application RUN cargo build --release
# Build the application List files in the target directory to check if the binary was created
RUN cargo build --releaseRUN ls -la ./target/release/

# Expose the necessary port (replace with the actual port if needed) List files in the target directory to check if the binary was createdEXPOSE 8080
RUN ls -la ./target/release/
# Set the CMD to run the binary with backtrace for debugging Expose the necessary port (replace with the actual port if needed)CMD ["sh", "-c", "RUST_BACKTRACE=full ./target/release/ants"]
EXPOSE 8080
# Set the CMD to run the binary with backtrace for debugging
CMD ["sh", "-c", "RUST_BACKTRACE=full ./target/release/ants"]


