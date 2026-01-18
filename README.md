<p align="left">
  <img src="assets/nc2026.gif" alt="nc 2026 banner">
</p>

# Netcat 2.0 (The "2026" Release)

Netcat is—still—a simple Unix utility which reads and writes data across network connections. It has been thirty years. You would think by now we would have telepathic interfaces or at least a better way to move bytes than raw TCP, yet here we are. It remains a reliable "back-end" tool, but the engine under the hood is being swapped out.

        /_/\        [ IPv6 / QUIC / io_uring ]
       / o O

      ====v====
       \  W  /
       |     |     _
       / ___ \    /
      / /   \ \  |
     (((-----)))-'
      /
     (      ___
      __.=|___E
             /

## Roadmap: What's New for 2026?

The internet is a darker, faster, and more encrypted place than it was in 1996. The following features are planned for the upcoming Netcat 2.0 release (see `TODO.md`):

*   **io_uring Support:** We no longer block. We submit rings. The data transfer loop becomes asynchronous and zero-copy.
*   **Kernel TLS (KTLS):** Netcat will offload encryption to the Linux kernel.
*   **eBPF Filter Injection:** Attach classic BPF or modern eBPF programs to the socket to filter packet garbage.
*   **Multipath TCP (MPTCP):** Because sometimes one interface isn't enough.
*   **Namespace Awareness:** Enter and exit network namespaces (`netns`) without needing `ip netns exec`.

---

## Basic Usage & Documentation

In the simplest usage, `nc host port` creates a TCP connection to the given port on the given target host. Your standard input is then sent to the host, and anything that comes back across the connection is sent to your standard output. This continues indefinitely, until the network side of the connection shuts down. Note that this behavior is different from most other applications which shut everything down and exit after an end-of-file on the standard input.

Netcat can also function as a server, by listening for inbound connections on arbitrary ports and then doing the same reading and writing. With minor limitations, netcat doesn't really care if it runs in "client" or "server" mode -- it still shovels data back and forth until there isn't any more left.

### Building

Compiling is straightforward. We use the Meson build system.

```bash
meson setup builddir
cd builddir
ninja
```

### Major Features

*   Outbound or inbound connections, TCP or UDP, to or from any ports
*   Full DNS forward/reverse checking, with appropriate warnings
*   Ability to use any local source port
*   Ability to use any locally-configured network source address
*   Built-in port-scanning capabilities, with randomizer
*   Built-in loose source-routing capability
*   Can read command line arguments from standard input
*   Slow-send mode, one line every N seconds
*   Hex dump of transmitted and received data
*   Optional ability to let another program service established connections

### Exploration of Features

**Command Line Arguments**
If no command arguments are given at all, netcat asks for them, reads a line from standard input, and breaks it up into arguments internally. This can be useful when driving netcat from certain types of scripts, with the side effect of hiding your command line arguments from `ps` displays.

**Hostnames & DNS (-n)**
The host argument can be a name or IP address. If `-n` is specified, netcat will only accept numeric IP addresses and do no DNS lookups for anything. If `-n` is not given and `-v` is turned on, netcat will do a full forward and reverse name and address lookup for the host, and warn you about the all-too-common problem of mismatched names in the DNS.

**Verbosity & Timeouts (-v, -w)**
The `-v` switch controls the verbosity level of messages sent to standard error. You will probably want to run netcat most of the time with `-v` turned on. You will probably also want to give a smallish `-w` argument, which limits the time spent trying to make a connection. The timeout is easily changed by a subsequent `-w` argument which overrides the earlier one. Specifying `-v` more than once makes diagnostic output MORE verbose.

**UDP Mode (-u)**
UDP connections are opened instead of TCP when `-u` is specified. These aren't really "connections" per se since UDP is a connectionless protocol, although netcat does internally use the "connected UDP socket" mechanism that most kernels support. Although netcat claims that an outgoing UDP connection is "open" immediately, no data is sent until something is read from standard input.

**Hex Dump (-o)**
To obtain a hex dump file of the data sent either way, use `-o logfile`. The dump lines begin with `<` or `>` to respectively indicate "from the net" or "to the net", and contain the total count per direction, and hex and ascii representations of the traffic.

**Binding to Ports (-p, -s, -l)**
Netcat can bind to any local port, subject to privilege restrictions and ports that are already in use. Use `-p portarg` to grab a specific local port, and `-s ip-addr` to have that be your source IP address. Listen mode (`-l`) will cause netcat to wait for an inbound connection, and then the same data transfer happens.

**Port Scanning (-z, -r)**
Port-scanning is a popular method for exploring what's out there. Netcat accepts its commands with options first, then the target host, and everything thereafter is interpreted as port names or numbers.
Example: `nc -v -w 2 -z target 20-30` will try connecting to every port between 20 and 30 at the target. The `-z` switch prevents sending any data to a TCP connection and very limited probe data to a UDP connection. If `-r` is used, scanning hops randomly around within that range.

**Source Routing (-g, -G)**
On systems that support it, the `-g` switch can be used multiple times [up to 8] to construct a loose-source-routed path for your connection, and the `-G` argument positions the "hop pointer" within the list.

### Example Uses -- The Light Side

**Data Transfer**
Netcat can be used as a simple data transfer agent. A typical example of something `rsh` is often used for:
Receiver: `nc -l -p 1234 | uncompress -c | tar xvfp -`
Sender: `tar cfp - /some/dir | compress -c | nc -w 3 othermachine 1234`

**Talking to Servers**
It is sometimes useful to talk to servers "by hand" rather than through a user interface.
Example: `echo "QUIT" | nc host.example.com 20-30`
This allows you to see the greeting banner from servers, identifying the software they are running.

**Web Browser Scripting**
An example of netcat as a backend for something else is the shell-script Web browser, which simply asks for the relevant parts of a URL and pipes `GET /what/ever` into a netcat connection to the server.

### Example Uses -- The Dark Side

**Scanning**
The first obvious thing is scanning someone *else's* network for vulnerable services. Files containing preconstructed data can be fed in as standard input. The more random the scanning, the less likelihood of detection by humans or scan-detectors.

**Server Takeover (-e)**
Using `-e` in conjunction with binding to a specific address can enable "server takeover" by getting in ahead of the real ones. If you are root, you can use `-s` and `-e` to run various hacked daemons without having to touch `inetd.conf` or the real daemons themselves.

**Spoofing**
Got an unused network interface configured in your kernel [e.g. SLIP], or support for alias addresses? Ifconfig one to be any address you like, and bind to it with `-s` to enable all sorts of shenanigans with bogus source addresses.

---
*Original Netcat by Hobbit. Reimagined for 2026.*
