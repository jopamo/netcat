# Netcat (Based on Hobbit's BSD Version)

       /\_/\
      / 0 0 \
    ====v====
      \  W  /
      |     |     _
      / ___ \    /
    (((-----)))-'
       /
     (      ___
      \__.=|___E


Netcat (`nc`) is a simple Unix utility which reads and writes data across network connections, using the TCP or UDP protocol.
It is designed to be a reliable "back-end" tool that can be used directly or easily driven by other programs and scripts.
At the same time, it is a feature-rich network debugging and exploration tool, able to create almost any kind of connection you need.
WS
> **Netcat, or "nc" as the actual program is named, should have been supplied long ago as another one of those cryptic but standard Unix tools.**

---

## What is Netcat?

In its simplest use, `nc host port` creates a TCP connection to the given port on the given target host.
Your standard input is sent to the host, and anything that comes back is sent to your standard output.
This continues until the network side of the connection shuts down.
Unlike most other applications, Netcat does **not** exit after an end-of-file on standard input—it stays running until the network closes.

Netcat can also function as a server, listening for inbound connections on arbitrary ports.
It doesn't really care if it runs in "client" or "server" mode—it simply shovels data back and forth until there isn't any more left.

It can also do this via UDP, making Netcat a "udp telnet-like" application for testing UDP-mode servers.

---

## Major Features

- Outbound or inbound connections, TCP or UDP, to/from any ports
- Full DNS forward/reverse checking, with appropriate warnings
- Ability to use any local source port and/or source address
- Built-in port-scanning capabilities, with randomizer
- Loose source-routing support
- Reads command line arguments from standard input
- Slow-send mode (one line every N seconds)
- Hex dump of transmitted and received data
- Optional "exec" of another program for established connections
- Optional telnet-options responder

---

## Building

Run `make` to build Netcat.
Check the Makefile for any system-specific flags or dependencies.

Typical build:

```sh
make
````

The binary will be named `nc`.

---

## Usage

* Outbound connection:

  ```sh
  nc example.com 80
  ```

* Inbound "server" mode:

  ```sh
  nc -l -p 1234
  ```

* UDP mode:

  ```sh
  nc -u example.com 1234
  ```

* Port scan with randomizer:

  ```sh
  nc -v -z -r example.com 20-80
  ```

See `nc.1` for the full man page and more options.
