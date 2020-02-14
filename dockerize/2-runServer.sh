docker run --network=host --rm --detach --name=rendezvous-server --volume=${PWD}/..:/root --volume=/var/run/docker.sock:/var/run/docker.sock rendezvous rendezvous -f config-server.yaml
