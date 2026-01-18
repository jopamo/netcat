Here is the expanded, comprehensive TODO list for the Netcat 2026 release. It integrates the core kernel updates, the new cloud-native protocols, and the advanced security features discussed.

# Netcat 2.0 ("The 2026 Release") Expanded TODO List

### 1. Core Kernel & Performance

*Modernizing the engine for speed and kernel-level efficiency.*

* [ ] **io_uring Support**: Implement asynchronous I/O engine using `liburing` to replace the legacy `poll()/select()` loop.
* *Goal:* Saturate 100GbE links with minimal syscall overhead.
* *Flag:* `-U`
* *Status:* Blocked (liburing not found in environment)


* [x] **Zero-Copy Splice**: Implement `splice()`/`sendfile()` based data transfer for file redirection.
* *Goal:* Move data directly from socket to disk buffer without touching user-space RAM.
* *Flag:* `--splice` or `-Z`


* [x] **Multipath TCP (MPTCP)**: Enable MPTCP support (`IPPROTO_MPTCP`) for socket connections.
* *Goal:* Allow connections to aggregate bandwidth across multiple interfaces (e.g., WiFi + Ethernet).
* *Flag:* `--mptcp`


* [x] **TCP Fast Open (TFO)**: Implement `TCP_FASTOPEN` support.
* *Goal:* Send data in the initial SYN packet to reduce latency for short transactions.
* *Flag:* `--tfo`


* [x] **Socket Priority/Marking**: Add support for `SO_MARK` and `SO_PRIORITY`.
* *Goal:* Tag packets for QoS queues or specific firewall routing tables.
* *Flag:* `--mark <int>`



### 2. Encryption & Modern Protocols

*Moving beyond plain TCP/UDP.*

* [ ] **Kernel TLS (KTLS)**: Implement `ULP_KTLS` support for hardware-offloaded encryption.
* *Goal:* Encryption at wire speed without linking OpenSSL.
* *Flag:* `-k` (`--tls-cert`, `--tls-key`)


* [ ] **HTTP/3 (QUIC) Probing**: Add basic QUIC handshake initiation over UDP.
* *Goal:* Detect QUIC-capable endpoints and test UDP 443 connectivity.
* *Flag:* `--quic`


* [x] **DTLS Support**: Implement Datagram TLS for UDP encryption.
* *Goal:* Secure UDP streams for WebRTC/VPN debugging.
* *Flag:* `--dtls`


* [x] **Proxy Protocol v2**: Implement parsing (server) and injection (client) of the PROXY header.
* *Goal:* Debug load balancers and Ingress controllers while preserving/spoofing client IPs.
* *Flag:* `--proxy-proto` (listener), `--send-proxy` (client)



### 3. Cloud Native & Virtualization

*Speaking the language of containers and hypervisors.*

* [x] **AF_VSOCK Support**: Implement addressing for Virtual Sockets.
* *Goal:* Communication between Host and Guest VMs/Enclaves without TCP/IP.
* *Flag:* `--vsock <CID> <PORT>`


* [x] **Namespace Awareness**: Implement `setns()` logic to enter network namespaces (netns) before binding.
* *Goal:* Bind ports inside Docker/Podman containers from the host.
* *Flag:* `--namespace /var/run/netns/<name>`


* [x] **Abstract Unix Sockets**: Support Linux abstract namespace (non-filesystem) Unix sockets.
* *Goal:* Interacting with hidden IPC mechanisms and Android system services.
* *Syntax:* `nc -l -U @hidden_socket`



### 4. Observability & Logging

*Making output machine-readable.*

* [x] **Structured JSON Output**: Replace unstructured text logs with NDJSON.
* *Goal:* Pipe output directly to `jq`, Splunk, or ELK stacks.
* *Flag:* `-j`


* [x] **Internal PCAP Dump**: Implement a mini packet capture writer.
* *Goal:* Dump the specific session traffic to a `.pcap` file without needing root for `tcpdump`.
* *Flag:* `--pcap <file>`


* [x] **Enhanced Hex Dump**: Update the `-x` / `-o` hex dump logic.
* *Goal:* Ensure hex dumps align correctly with `diff` for binary protocol reverse engineering.
* *Flag:* `--hex-dump <file>`



### 5. Security & Offensive Research ("The Dark Side")

*Features for penetration testing and rigorous debugging.*

* [ ] **eBPF Filter Injection**: Allow attaching pre-compiled eBPF (`SO_ATTACH_BPF`) programs to the socket.
* *Goal:* High-performance packet filtering and traffic shaping at the kernel level.
* *Flag:* `--bpf-prog <obj_file>`


* [x] **Internal Fuzzer**: Add a random data generator source.
* *Goal:* Flood a socket with random noise without needing `/dev/urandom` piping.
* *Flag:* `--fuzz-tcp` / `--fuzz-udp`


* [ ] **Robust Server Takeover**: Refactor the `-e` (exec) logic.
* *Goal:* Ensure `GAPING_SECURITY_HOLE` works reliably with `io_uring` and MPTCP, resisting modern EDR heuristics where possible.


* [ ] **Advanced Source Spoofing**: Improve `-s` (source IP) and `-p` (source port) logic.
* *Goal:* Ensure aliased interfaces and secondary IPs are correctly handled for firewall evasion.



### 6. Build & Documentation

* [ ] **Build System**: Update `meson.build` or `Makefile` to detect:
* Kernel version (>= 5.10 for io_uring/KTLS).
* `liburing` presence.
* `libcap` (if needed for namespace operations).


* [ ] **Man Page Update**: Rewrite `nc.1` to document the new flags.
* [ ] **Migration Guide**: Add a section in `README` explaining how to migrate from `socat` or `ncat` to `nc 2.0`.
