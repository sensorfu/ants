# Use an official lightweight Linux distribution as a base
FROM alpine:latest

# Install nmap
RUN apk update && apk add --no-cache nmap

# Set the default command to run nmap
CMD ["nmap", "--help"]


