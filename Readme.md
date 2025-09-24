# Overview
This repository contains an example AF_XDP client and server implementation in Go


# Requirements
```bash
sudo apt install clang llvm libelf-dev libpcap-dev build-essential libc6-dev-i386 m4 libbpf-dev
```

# env setup
```bash
eval $(./env/testenv.sh alias)
```
Use `t` to test the environment setup.

```bash
t setup --name afxdp
```
To clean 
```bash
t teardown
```

# Build & Run 
```bash
make run
```
This starts the server application with AF_XDP enabled

# Setup Client application
> [!NOTE]
> VERY IMPORTANT:
> ```bash
> sudo ip netns exec afxdp bash 
> sudo ip link set dev veth0 mtu 3000 # inside the namespace
> ```
> 
> ```bash
> sudo ip link set dev afxdp mtu 3000 # outside the namespace
> ```

Exec into the network namespace `afxdp` to run the client application.
```bash
sudo ip netns exec afxdp bash 
```

## another scenario 

Use benchmark folder to test normal key exchange with new mechanism. There are two binaries in [bin](benchmark/bin/) folder `client` and `server`. client can also used with afxdp server.

for usage: 
```bash
./server -h
./client -h
```

