# **Rendezvous**

Rendezvous is an application for testing communication between server and clients. The Rendezvous client scans the specified server IP address and ports to verify that the ports are open. 

Also, Rendezvous can gather various information such as OS type of server through http communication. If you have Docker installed on your server, Rendezvous can also check whether the specified Docker image is installed.

## Build

```
# go build
```

## Quick Start

1. Run Rendezvous on server machine 
   (When multiple ports to be tested, use "-p" flag repeatedly)

   ```
   # rendezvous server -v -p 7050 -p 7051
   ```

   After Rendezvous server started up,  you can see following output:

   ```
   ------------------------------
   Config:
    {
     "ServerMode": true,
     "Verbose": true,
     "ServerConfig": {
       "Ports": [
         "7050",
         "7051"
       ]
     }
   }
   ------------------------------
   
   Docker client API version: 1.40
   [ 0 ] Listen on http://127.0.0.1:7050/ ...
   [ 1 ] Listen on http://127.0.0.1:7051/ ...
   ```

2. Run Rendezvous on client machine

   ```
   # rendezvous client -v -r -a 172.27.26.82 -p 7050 -p 7051
   ```

   ```
   ===== [ 0 ] Target server: 172.27.26.82 =====
   
     ********** [Port 7050] **********
     Port open OK
     HTTP response OK
   
     ********** [Port 7051] **********
     Port open OK
     HTTP response OKdf
   ```

3. Check if a specific Docker image is installed on the server

   - For example, "hello-world" image in the server that has 'latest' tag and image ID 'fce289e99eb9'
   - When specifying multiple images at the same time, you can use "-i" flag repeatedly.

   ```
   # rendezvous client -v -r -t 172.27.26.82 -p 7050 -p 7051 -i hello-world:latest:fce289e99eb9
   ```

   ```
   ===== [ 0 ] Target server: 172.27.26.82 =====
   ...
   Same as above
   ...
     ********** [ Docker Check Images ] **********
     hello-world:latest:fce289e99eb9 --> found
   ```

## Detailed setting

- The yaml file allows you to make various settings. (config-server.yaml, config-client.yaml)
- You can set server or client mode via the "ServerMode" variable in yaml file

1. Run on server machine

   ```
   # rendezvous -f config-server.yaml
   ```

2. Do the same on the client machine

   ```
   # rendezvous -f config-client.yaml
   ```


## Docker

- Rendezvous can also be run in docker

  https://hub.docker.com/repository/docker/dryun/rendezvous

- In the command below, [yaml file directory] should be replaced with the directory where config-server.yaml and config-client.yaml files are located.

1. Run on server machine

   ```
   # docker run --tty --network=host --rm --volume=[yaml file directory]:/root/yaml --volume=/var/run/docker.
   sock:/var/run/docker.sock dryun/rendezvous:latest rendezvous -f yaml/config-server.yaml
   ```
   
2. Client machine

   ```
   # docker run --tty --rm --volume=[yaml file directory]/root/yaml dryun/rendezvous:latest rendezvous -f yaml/config-client.yaml
   ```
