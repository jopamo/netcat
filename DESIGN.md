# DESIGN

## High-Level Architecture

- Meson drives the build and emits `config.h` with feature toggles (notably IPv6). Optional feature flags map directly to compile-time defines.
- A single modular codepath in `src/` builds the installed `nc` binary.
- Source is organized by responsibility: connection logic, context management, resolution, protocol helpers, and I/O pumping live in separate translation units.

## Core Components

- `src/nc_ctx.[ch]`: centralized runtime state, option flags, counters, and resolved addresses shared across modules.
- `src/resolve.c`: host/port parsing via `getaddrinfo`/`getnameinfo`, port range handling, and optional random port selection.
- `src/connect.c`: socket creation, optional local bind, IPv4/IPv6-aware connection setup with nonblocking timeouts, listen/accept helpers, and UDP port verification.
- `src/io_pump.c`: bridges stdin/stdout to the network socket, handling line-interval throttling, TELNET negotiation, hexdumps, zero-I/O scans, and byte counters.
- `src/telnet.c`: TELNET option responder used when `-t` is compiled in.
- `src/hexdump.c`: writes formatted hex/ASCII traffic logs for sent/received directions.
- `src/exec.c`: redirects the socket to stdio and execs a user-specified program or shell command when compiled with the dangerous exec option.

## Data Flow

1. Arguments populate `nc_ctx` (`nc_ctx_init` + `getopt` parsing) and decide protocol, bind/target addresses, and optional features (hexdump, TELNET, exec).
2. Destination and optional source addresses resolve through `nc_resolve_one`/`nc_resolve_local_address`; port ranges may be randomized before connection attempts.
3. `nc_connect` (or listen/accept in server mode) creates the socket with basic reuse/broadcast options, honors timeouts via `poll`, and records the peer.
4. In connect mode, optional UDP validation may occur. If exec is enabled, stdio is redirected and the requested program is launched.
5. Otherwise, `nc_pump_io` relays between stdin/stdout and the socket, performing TELNET negotiation when compiled in and streaming traffic through the hexdump logger when requested. EOF/timeout handling controls shutdown, especially for scans or zero-I/O runs.
6. Context teardown closes descriptors and frees buffers before exit.

## Decision Log

- Meson is authoritative for configuration; IPv6 is a feature flag (`-Dipv6`) that defaults to disabled unless explicitly requested and supported by headers.
- TELNET negotiation (`-Dtelnet`) and verbose debug (`-Dverbose_debug`) are optional compile-time toggles; exec support requires `-Dexec_hole` to avoid accidental backdoors.
- The modern path uses `getaddrinfo`/`getnameinfo` for resolver correctness and employs nonblocking `connect` plus `poll` for timeouts; I/O still uses a select-based pump for compatibility while a poll-based loop is staged.
- The modular implementation is the single codepath for `nc`.
