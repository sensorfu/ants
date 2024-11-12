FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y nmap netcat-openbsd iputils-ping hping3 tcpdump && \
    rm -rf /var/lib/apt/lists/*
    
CMD ["bash"]
