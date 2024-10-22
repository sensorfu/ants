Relevant work:
https://www.cmand.org/papers/degreaser-acsac14.pdf


# Docker running

First create docker images of ants and nmap scanner

```console
docker build -f ants.dockerfile -t ants1 . && docker build -f nmap.dockerfile -t my_nmap .
```

Then create a testnetwork

```console
docker network create -d bridge --subnet=172.19.0.0/16 my_custom_bridge
```

Lastly compose and run containers

```console
docker-compose up
```

