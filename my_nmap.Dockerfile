FROM alpine:latest

RUN apk update && apk add --no-cache nmap

CMD ["nmap", "--help"]


