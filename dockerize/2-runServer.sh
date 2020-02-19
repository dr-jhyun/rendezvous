docker run --tty --network=host --rm --volume=${PWD}/..:/root/yaml --volume=/var/run/docker.sock:/var/run/docker.sock dryun/rendezvous:1.0.0 rendezvous -f yaml/config-server.yaml
