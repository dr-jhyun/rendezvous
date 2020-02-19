docker run --tty --network=host --rm --volume=${PWD}/..:/root/yaml --volume=/var/run/docker.sock:/var/run/docker.sock dryun/rendezvous:latest rendezvous -f yaml/config-server.yaml
