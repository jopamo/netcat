# Netcat

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

Netcat (`nc`) here is a C17 rewrite/fork of the classic Hobbit BSD release (help banner still reports `[v1.10]`). It keeps the original feel while using Meson/Ninja, `getaddrinfo`, and nonblocking I/O.

## Quick usage

```sh
$ nc -h
[v1.10]
connect to somewhere:  nc [-options] hostname port[s] [ports] ...
listen for inbound:    nc -l -p port [-options] [hostname] [port]
```

- TCP client: `./build/nc example.com 80`
- TCP listener: `./build/nc -l -p 1234`
- UDP: `./build/nc -u example.com 1234`
- Port scan: `./build/nc -v -z -r example.com 20-80`

Source routing options (-g/-G) have been removed; this fork intentionally omits the legacy LSRR/SSRR code paths. The manual now lives at `man/nc.1`; contributor notes are in `HACKING.md` and architecture notes in `DESIGN.md`.

## Build

```sh
meson setup build -Dipv6=disabled -Dtelnet=true -Dexec_hole=false
meson compile -C build
./build/nc -h
```

Feature flags: `-Dipv6=enabled|disabled|auto`, `-Dtelnet=true|false`, `-Dverbose_debug=true|false`, `-Dexec_hole=true|false` (enables `-e`/`-c`).

## Option examples (one for every supported flag)

- `-4` IPv4 only: `nc -4 example.com 80`
- `-6` IPv6 only (build with `-Dipv6=enabled`): `nc -6 2001:db8::1 443`
- `-b` Allow broadcast (UDP): `echo hi | nc -u -b 255.255.255.255 9999`
- `-c cmd` Exec via `/bin/sh` (requires `-Dexec_hole=true`): `nc -c 'echo hi' example.com 80`
- `-e prog` Exec program (requires `-Dexec_hole=true`): `nc -e /usr/bin/id example.com 80`
- `-h` Help banner: `nc -h`
- `-i secs` Delay between sends/scans: `nc -i 2 -v -z target 20-30`
- `-l` Listen mode: `nc -l -p 1234`
- `-n` Numeric-only addresses: `nc -n 192.0.2.10 22`
- `-o file` Hex dump traffic: `nc -o traffic.hex example.com 443`
- `-p port` Local source port: `nc -p 4444 example.com 80`
- `-q secs` Quit after stdin EOF + delay: `echo hi | nc -q 1 example.com 80`
- `-r` Randomize port order: `nc -v -z -r target 1-1024`
- `-s addr` Local source address: `nc -s 192.0.2.15 example.com 80`
- `-t` Answer TELNET negotiation (build with `-Dtelnet=true`): `nc -t telnet.example.com 23`
- `-u` UDP mode: `nc -u example.com 9999`
- `-v` Verbose (repeat for more): `nc -v example.com 80`
- `-w secs` Timeout for connects/reads: `nc -w 3 example.com 80`
- `-z` Zero-I/O scan mode: `nc -v -z example.com 22-25`

## Extensions

- Exec modes close all file descriptors except stdin/stdout/stderr before launching the child; use `--exec-inherit-fds` (requires `-Dexec_hole=true`) to keep inherited descriptors when you explicitly need them.

## Notes

- Hex dumps with `-o` disable when exec-after-connect is requested (`-e`/`-c`) for safety.
- If no args are given, `nc` reads a command line from stdin (mirrors historical behavior).
- IPv6 support depends on headers present and the Meson `ipv6` feature switch.
