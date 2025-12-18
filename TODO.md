# TODO.md — Modernize legacy nc-style codebase (C11 + Meson)

Goal: Rework the K&R-era netcat-like implementation into modern, maintainable C11
Constraints:
- [x] IPv6 is **optional** via Meson feature and **disabled by default**
- [x] Remove IP_OPTIONS / LSRR and all source-routing flags/paths
- [x] Keep exec feature (dangerous) and keep TELNET negotiation
- [ ] Replace `select()` + FD_SETSIZE hacks and `alarm/setjmp` timeouts with nonblocking + `poll()`
- [ ] Replace `gethostbyname/gethostbyaddr/h_errno/res_init` with `getaddrinfo/getnameinfo`

## Original CLI compatibility backlog

- [ ] Reintroduce historical source-routing flags `-g`/`-G` (currently removed for safety/portability) or document a deliberate deprecation plan.

---

## 0) Project structure split

- [x] Create modules (even if you keep a single binary)
  - [x] `src/main.c` CLI + wiring
  - [x] `src/nc_ctx.h` / `src/nc_ctx.c` global state -> context struct
  - [x] `src/resolve.c` address resolution
  - [x] `src/connect.c` connect/listen helpers
  - [x] `src/io_pump.c` bidirectional copy loop using poll
  - [x] `src/telnet.c` TELNET negotiation helper
  - [x] `src/hexdump.c` optional traffic dump (if you keep `-o file`)
  - [x] `src/exec.c` exec feature (gated, explicit warnings)

---

## 1) Meson: IPv6 optional feature, default disabled

- [x] Add a Meson feature option (default `disabled`)
  - [x] `meson_options.txt`

```meson
option('ipv6', type: 'feature', value: 'disabled', description: 'Enable IPv6 support')
````

- [x] In `meson.build`, detect headers and set a config define

```meson
project('nc', 'c', default_options: ['c_std=c11', 'warning_level=3'])

cc = meson.get_compiler('c')

ipv6_opt = get_option('ipv6')
have_inet6 = cc.has_header('netinet/in.h') and cc.has_header('arpa/inet.h')

ipv6_enabled = false
if ipv6_opt.enabled()
  if have_inet6
    ipv6_enabled = true
  else
    error('ipv6 enabled but required headers not found')
  endif
endif

conf = configuration_data()
conf.set10('NC_ENABLE_IPV6', ipv6_enabled)
configure_file(output: 'config.h', configuration: conf)

executable('nc',
  sources: [
    'src/main.c',
    'src/nc_ctx.c',
    'src/resolve.c',
    'src/connect.c',
    'src/io_pump.c',
    'src/telnet.c',
    'src/exec.c',
    'src/hexdump.c',
  ],
  include_directories: include_directories('.'),
)
```

- [x] In C, include config and guard IPv6 code

```c
#include "config.h"

#if NC_ENABLE_IPV6
  #define NC_HAVE_IPV6 1
#else
  #define NC_HAVE_IPV6 0
#endif
```

---

## 2) Delete IP_OPTIONS / LSRR and related CLI flags

- [x] Remove:

  - [x] `-g`, `-G`, `gatesidx`, `gatesptr`, `gates` arrays
  - [x] `optbuf` source-routing builder
  - [x] any `#ifdef IP_OPTIONS` blocks
- [x] Update help text accordingly

Code example (what stays): nothing
Code example (what gets deleted): all `setsockopt(..., IP_OPTIONS, ...)` paths

---

## 3) Replace global variables with a single context struct

- [ ] Create `struct nc_ctx` and pass it everywhere

`src/nc_ctx.h`:

```c
#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

enum nc_proto { NC_TCP, NC_UDP };

struct nc_ctx {
    enum nc_proto proto;

    bool listen_mode;
    bool numeric_only;
    bool verbose;
    bool allow_broadcast;
    bool zero_io;
    bool telnet;
    bool hexdump_enabled;

    int interval_secs;
    int timeout_secs;
    int quit_after_eof_secs;

    FILE* log_out;
    int hexdump_fd;

    uint64_t wrote_out;
    uint64_t wrote_net;

    const char* exec_prog;
    bool exec_use_sh;
};
```

- [ ] Replace `holler/bail` with modern logging helpers

```c
static void nc_logf(struct nc_ctx* ctx, const char* fmt, ...) {
    if (!ctx->verbose)
        return;

    FILE* out = ctx->log_out ? ctx->log_out : stderr;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(out, fmt, ap);
    va_end(ap);
    fputc('\n', out);
    fflush(out);
}

static void nc_die(struct nc_ctx* ctx, const char* fmt, ...) {
    FILE* out = ctx->log_out ? ctx->log_out : stderr;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(out, fmt, ap);
    va_end(ap);

    if (errno)
        fprintf(out, ": %s", strerror(errno));

    fputc('\n', out);
    exit(1);
}
```

---

## 4) Replace resolver code with getaddrinfo/getnameinfo

- [ ] Remove:

  - [ ] `struct host_poop`, `gethostpoop`, `gethost6poop`
  - [ ] `comparehosts*`, `h_errno`, `res_init`, resolver tables

- [ ] New helper: resolve one destination (first match)

`src/resolve.c`:

```c
#include <netdb.h>
#include <string.h>
#include <errno.h>

static int nc_socktype(enum nc_proto p) {
    return (p == NC_UDP) ? SOCK_DGRAM : SOCK_STREAM;
}

int nc_resolve_one(const char* host, const char* service,
                   int family, enum nc_proto proto,
                   struct sockaddr_storage* out, socklen_t* out_len,
                   bool numeric_only) {
    struct addrinfo hints = {0};
    hints.ai_family = family;               // AF_UNSPEC / AF_INET / AF_INET6
    hints.ai_socktype = nc_socktype(proto);
    hints.ai_flags = AI_ADDRCONFIG;
    if (numeric_only)
        hints.ai_flags |= AI_NUMERICHOST;

    struct addrinfo* res = NULL;
    int rc = getaddrinfo(host, service, &hints, &res);
    if (rc != 0)
        return -1;

    memcpy(out, res->ai_addr, res->ai_addrlen);
    *out_len = (socklen_t)res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}
```

- [ ] Optional: reverse lookup for verbose prints using `getnameinfo()`

```c
int nc_reverse_name(const struct sockaddr* sa, socklen_t slen,
                    char* host, size_t host_sz,
                    bool numeric_only) {
    int flags = numeric_only ? NI_NUMERICHOST : 0;
    return getnameinfo(sa, slen, host, host_sz, NULL, 0, flags);
}
```

---

## 5) Connect timeout: remove alarm/setjmp and use nonblocking + poll

- [ ] Delete:

  - [ ] `jmp_buf`, `tmtravel`, `arm_timer`, all `setjmp/longjmp` usage

`src/connect.c`:

```c
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <errno.h>

int nc_connect_with_timeout(int fd, const struct sockaddr* sa, socklen_t slen, int timeout_secs) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;

    int rc = connect(fd, sa, slen);
    if (rc == 0)
        goto done;

    if (errno != EINPROGRESS)
        return -1;

    struct pollfd pfd = {0};
    pfd.fd = fd;
    pfd.events = POLLOUT;

    int ms = (timeout_secs > 0) ? timeout_secs * 1000 : -1;
    int prc = poll(&pfd, 1, ms);
    if (prc <= 0) {
        if (prc == 0)
            errno = ETIMEDOUT;
        return -1;
    }

    int soerr = 0;
    socklen_t olen = sizeof(soerr);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &olen) < 0)
        return -1;
    if (soerr != 0) {
        errno = soerr;
        return -1;
    }

done:
    (void)fcntl(fd, F_SETFL, flags);
    return 0;
}
```

---

## 6) Replace select()+FD_SETSIZE hacks with poll-based pump

- [ ] Delete:

  - [ ] `FD_SETSIZE` redefines
  - [ ] `ding1/ding2`, `select(16, ...)` calls
  - [ ] `findline()` throttling logic that assumes fixed sizes
- [ ] Implement a clean “pump” loop

`src/io_pump.c` (core skeleton):

```c
#include <poll.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

struct io_buf {
    unsigned char* data;
    size_t cap;
    size_t len;
    size_t off;
};

static bool buf_empty(const struct io_buf* b) {
    return b->off >= b->len;
}

static void buf_reset(struct io_buf* b) {
    b->len = 0;
    b->off = 0;
}

static ssize_t buf_read_into(int fd, struct io_buf* b) {
    if (b->len != 0)
        return 0;
    ssize_t r = read(fd, b->data, b->cap);
    if (r > 0) {
        b->len = (size_t)r;
        b->off = 0;
    }
    return r;
}

static ssize_t buf_write_from(int fd, struct io_buf* b) {
    if (buf_empty(b))
        return 0;
    ssize_t r = write(fd, b->data + b->off, b->len - b->off);
    if (r > 0) {
        b->off += (size_t)r;
        if (buf_empty(b))
            buf_reset(b);
    }
    return r;
}

int nc_pump_io(struct nc_ctx* ctx, int netfd,
               struct io_buf* to_net, struct io_buf* to_out) {
    bool stdin_open = true;

    for (;;) {
        struct pollfd pfds[2] = {0};
        nfds_t n = 0;

        // netfd
        pfds[n].fd = netfd;
        pfds[n].events = 0;
        if (to_out->len == 0)
            pfds[n].events |= POLLIN;
        if (!buf_empty(to_net))
            pfds[n].events |= POLLOUT;
        n++;

        // stdin
        if (stdin_open) {
            pfds[n].fd = STDIN_FILENO;
            pfds[n].events = (to_net->len == 0) ? POLLIN : 0;
            n++;
        }

        int ms = (ctx->timeout_secs > 0) ? ctx->timeout_secs * 1000 : -1;
        int prc = poll(pfds, n, ms);
        if (prc < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (prc == 0) {
            // timeout
            errno = ETIMEDOUT;
            return -1;
        }

        // net readable -> stdout buffer
        if (pfds[0].revents & POLLIN) {
            ssize_t r = buf_read_into(netfd, to_out);
            if (r == 0)
                return 0; // net closed
            if (r < 0 && errno != EINTR)
                return -1;

#ifdef TELNET
            if (ctx->telnet && to_out->len > 0) {
                nc_telnet_negotiate(ctx, netfd, to_out->data, to_out->len);
            }
#endif
        }

        // stdout writable -> flush stdout buffer
        if (!buf_empty(to_out)) {
            ssize_t w = buf_write_from(STDOUT_FILENO, to_out);
            if (w > 0)
                ctx->wrote_out += (uint64_t)w;
            if (w < 0 && errno != EINTR)
                return -1;
        }

        // stdin readable -> net buffer
        if (stdin_open && n == 2 && (pfds[1].revents & POLLIN)) {
            ssize_t r = buf_read_into(STDIN_FILENO, to_net);
            if (r == 0) {
                stdin_open = false;
                if (ctx->quit_after_eof_secs == 0) {
                    shutdown(netfd, SHUT_WR);
                }
            }
            if (r < 0 && errno != EINTR)
                return -1;
        }

        // net writable -> flush net buffer
        if (!buf_empty(to_net) && (pfds[0].revents & POLLOUT)) {
            ssize_t w = buf_write_from(netfd, to_net);
            if (w > 0)
                ctx->wrote_net += (uint64_t)w;
            if (w < 0 && errno != EINTR)
                return -1;
        }
    }
}
```

- [ ] Reintroduce “interval per line” cleanly (optional)

  - [ ] Instead of `findline()` + partial writes, implement:

    - [ ] if `interval_secs > 0`, only send up to newline per wake, then sleep

---

## 7) Telnet negotiation kept, but isolated

- [ ] Move TELNET logic into `src/telnet.c`
- [ ] Keep it pure: it should only inspect incoming bytes and write replies

Example stub:

```c
// telnet.c
#include <unistd.h>
#include <stdint.h>

void nc_telnet_negotiate(struct nc_ctx* ctx, int netfd, const unsigned char* buf, size_t len) {
    (void)ctx;

    // Minimal logic: when you see IAC (255), respond with DONT/WONT variants
    // Keep behavior compatible with your existing atelnet()
    // Important: do not block; write best-effort

    unsigned char reply[3];
    for (size_t i = 0; i + 2 < len; i++) {
        if (buf[i] != 255)
            continue;

        unsigned char cmd = buf[i + 1];
        unsigned char opt = buf[i + 2];

        unsigned char resp = 0;
        if (cmd == 251 || cmd == 252) // WILL/WONT
            resp = 254;               // DONT
        else if (cmd == 253 || cmd == 254) // DO/DONT
            resp = 252;                    // WONT

        if (resp) {
            reply[0] = 255;
            reply[1] = resp;
            reply[2] = opt;
            (void)write(netfd, reply, sizeof(reply));
        }
    }
}
```

---

## 8) Keep exec feature, but fence it hard

- [ ] Put exec in its own module and treat it as “dangerous”
- [ ] Avoid implicit shell unless user explicitly requests
- [ ] Prefer `execvp()` for direct exec; use `/bin/sh -c` only when asked

`src/exec.c`:

```c
#include <unistd.h>
#include <stdlib.h>

__attribute__((noreturn))
void nc_exec_after_connect(struct nc_ctx* ctx, int netfd) {
    if (!ctx->exec_prog)
        _exit(127);

    dup2(netfd, STDIN_FILENO);
    dup2(netfd, STDOUT_FILENO);
    dup2(netfd, STDERR_FILENO);
    close(netfd);

    if (ctx->exec_use_sh) {
        execl("/bin/sh", "sh", "-c", ctx->exec_prog, (char*)0);
        _exit(127);
    }

    // exec_prog is a path; execute it directly
    execl(ctx->exec_prog, ctx->exec_prog, (char*)0);
    _exit(127);
}
```

- [ ] Ensure CLI parsing forces explicit enable:

  - [ ] `-e /path/to/prog` direct exec
  - [ ] `-c "cmd"` shell exec

---

## 9) Remove “read argv from stdin” hack

The legacy code reads “Cmd line:” from stdin if argc==1. That’s weird and fragile.

- [ ] Delete that behavior entirely
- [ ] If you need “command from stdin”, add an explicit option later

---

## 10) Listening mode rework (TCP/UDP)

- [ ] Implement `nc_listen()` and `nc_accept()` for TCP
- [ ] For UDP listen:

  - [ ] bind and then `recvfrom(MSG_PEEK)` only if you really need “discover peer”
  - [ ] or simpler: just `recvfrom()` and then `connect()` the socket to that peer

Example snippet (UDP “lock to first peer”):

```c
// after bind()
struct sockaddr_storage peer = {0};
socklen_t peer_len = sizeof(peer);
unsigned char tmp[1];

ssize_t r = recvfrom(fd, tmp, sizeof(tmp), MSG_PEEK, (struct sockaddr*)&peer, &peer_len);
if (r >= 0) {
    if (connect(fd, (struct sockaddr*)&peer, peer_len) < 0)
        return -1;
}
```

---

## 11) CLI/Help modernization

- [ ] Convert all K&R function defs to ANSI prototypes

- [ ] Replace unsafe formatting and fixed buffers with `snprintf`

- [ ] Keep flags you want:

  - [ ] `-4` (force IPv4)
  - [ ] `-6` (force IPv6) only if `NC_ENABLE_IPV6` else error
  - [ ] `-l` listen
  - [ ] `-p` local port
  - [ ] `-s` local source address
  - [ ] `-u` UDP
  - [ ] `-v` verbose
  - [ ] `-n` numeric-only
  - [ ] `-w secs` timeout
  - [ ] `-i secs` interval
  - [ ] `-z` zero-IO scanning
  - [ ] `-t` telnet negotiation
  - [ ] `-o file` hexdump file
  - [ ] `-q secs` quit delay after stdin EOF
  - [ ] `-e prog` exec
  - [ ] `-c cmd` shell exec

- [ ] Remove flags related to LSRR/source routing:

  - [x] `-g`, `-G` gone
  - [ ] `-a` all-A-records: either remove or implement properly with getaddrinfo iteration

---

## 12) Hexdump: keep but modernize

- [ ] Move hexdump formatting into `src/hexdump.c`
- [ ] Don’t use magic offsets and fixed “stage” buffers
- [ ] Use a single line builder with bounded writes

Example simple dumper:

```c
void nc_hexdump_write(int fd, const unsigned char* buf, size_t len, uint64_t base) {
    char line[128];
    for (size_t off = 0; off < len; off += 16) {
        size_t n = len - off;
        if (n > 16) n = 16;

        int p = snprintf(line, sizeof(line), "%08llx  ", (unsigned long long)(base + off));
        for (size_t i = 0; i < 16; i++) {
            if (i < n) p += snprintf(line + p, sizeof(line) - p, "%02x ", buf[off + i]);
            else       p += snprintf(line + p, sizeof(line) - p, "   ");
        }
        p += snprintf(line + p, sizeof(line) - p, " |");
        for (size_t i = 0; i < n; i++) {
            unsigned char c = buf[off + i];
            line[p++] = (c >= 32 && c < 127) ? (char)c : '.';
        }
        line[p++] = '|';
        line[p++] = '\n';
        (void)write(fd, line, (size_t)p);
    }
}
```

---

## 13) Security and hardening toggles

- [ ] Add build flags in Meson for hardening

  - [ ] `-D_FORTIFY_SOURCE=2` (glibc), `-fstack-protector-strong`, `-fPIE`, `-pie`, `-Wl,-z,relro,-z,now`
- [ ] Treat exec as a deliberate choice; print warning

---

## 14) Testing checklist

- [ ] IPv4 TCP connect: `./nc host 80`
- [ ] IPv4 listen: `./nc -l -p 9999`
- [ ] UDP send/recv: `./nc -u host 9999`
- [ ] UDP listen + first peer connect: `./nc -u -l -p 9999`
- [ ] Telnet negotiation: connect to a telnet-ish endpoint and verify responses
- [ ] Exec:

  - [ ] `./nc -e /bin/cat host 9999`
  - [ ] `./nc -c "id" host 9999`
- [ ] Timeout: `-w 1` to a blackhole address should exit with ETIMEDOUT
- [ ] `-6` behavior:

  - [ ] with ipv6 disabled: print a clear error
  - [ ] with ipv6 enabled: connect/listen works

---

## 15) Cleanup list (things to delete entirely)

- [ ] K&R function definitions (all)
- [ ] `FD_SETSIZE` redefinition and `select(16, ...)`
- [ ] `alarm`, `signal(SIGALRM)`, `setjmp/longjmp`
- [ ] `gethostbyname`, `gethostbyaddr`, `getservby*` (optional; can keep `getservbyname` if you want)
- [x] `netinet/in_systm.h`, `netinet/ip.h` include soup
- [x] LSRR/IP_OPTIONS source routing (`-g`, `-G`, `gates*`)
- [ ] “read command line from stdin” argc==1 hack
