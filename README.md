# **Rendezvous**

Rendezvous is an application for testing communication between server and clients. The rendezvous client scans the specified server IP address and ports to verify that the ports are open. 

Also, you can check various information such as OS type of server through http communication. If you have Docker installed on your server, you can also verify that the specified Docker image is installed.

## Build

```
# export GO111MODULE=on
# go get github.com/docker/docker@master
# go build
```

## Quick Start

1. Run rendezvous on server machine 
   (When multiple ports to be tested, use "-p" flag repeatedly)

   ```
   # rendezvous -s -v -p 7050 -p 7051
   ```

   After rendezvous server started up,  you can see following output:

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

2. Run rendezvous on client machine

   ```
   # rendezvous -c 172.27.26.82 -p 7050 -p 7051
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

   - For example, "hello-world" image in the server has 'latest' tag and image ID 'fce289e99eb9'
   - When specifying multiple images at the same time, you can use "-i" flag repeatedly.

   ```
   # rendezvous -c 172.27.26.82 -p 7050 -p 7051 -i hello-world:latest:fce289e99eb9
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
- You can set server or client mode via the "ServerMode" variable.

1. Run on server machine

   ```
   # rendezvous -f config-server.yaml
   ```

2. Do the same on the client machine

   ```
   # rendezvous -f config-client.yaml
   ```

   
