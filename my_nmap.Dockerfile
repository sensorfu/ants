FROM ubuntu:latest

RUN apt-get update && apt-get install -y nmap

CMD ["bash"]
