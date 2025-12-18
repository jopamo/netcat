# TODO.md — Fork/rewrite Netcat

Goal: Rework the K&R-era netcat-like implementation into modern, maintainable C11 while preserving original CLI options and behavior by default, but improving low-level safety and robustness

Compatibility policy:
- Legacy flags keep exact semantics (including edge cases) unless explicitly documented as deprecated
- New useful behaviors must be added behind new options only (prefer long options to avoid collisions)
- “Better low-level stuff” is allowed as a default when it does not change flag meanings or user-visible I/O semantics

## Exec hardening default: close fds in child

You can do that, and it fits your “same flags, better low-level behavior” goal — as long as you treat it as an internal hardening default and provide an explicit escape hatch

Policy:
- When `-e` (or any exec mode) is used, default to: child inherits only fd 0/1/2
- Add a new option to disable it:
  - `--exec-inherit-fds` (recommended name)
  - or `--no-exec-close-fds`

This does not change the CLI meaning of `-e`; it only changes the child process environment, which is almost always a pure improvement (prevents leaking hexdump files, listening sockets, logs, etc). If someone had been relying on leaked fds (rare), they can opt out

Implementation shape

In `ctx`:

```c
// defaults
ctx->exec_close_fds = true;  // default ON
````

CLI parsing (new option only):

* `--exec-inherit-fds` → `ctx->exec_close_fds = false`

Exec path:

* `dup2(netfd, 0/1/2)` checked
* close original `netfd` if > 2
* if `ctx->exec_close_fds`: close everything >= 3
* exec

Use `close_range` when possible + portable fallback

```c
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>

static void nc_close_fds_keep_stdio(void) {
#if defined(__linux__) && defined(SYS_close_range)
    // close everything >= 3
    if (syscall(SYS_close_range, 3U, ~0U, 0U) == 0) return;
#endif
    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0) maxfd = 1024;
    for (int fd = 3; fd < maxfd; fd++) close(fd);
}
```

## Low-level robustness improvements that should be default

These are big wins that keep option semantics the same, but make the implementation sturdier

* Set CLOEXEC on every non-stdio fd by default

  * sockets, hexdump file, logs, temp files
  * reduces fd leaks even without exec-close-fds
* Avoid SIGPIPE surprises

  * use `send(..., MSG_NOSIGNAL)` when available, or ignore SIGPIPE early
* Poll loop correctness + robust EINTR handling

  * retry `poll/read/write` on EINTR
  * handle POLLHUP and POLLERR cleanly
* Prefer `accept4(..., SOCK_CLOEXEC)` when available

  * fallback to `accept` + `fcntl(FD_CLOEXEC)`
* Nonblocking connect done right

  * use `O_NONBLOCK + poll + getsockopt(SO_ERROR)`

Recommended new options (small, useful, no collisions):

* `--exec-inherit-fds` disable default close-fds hardening
* Optional future: `--exec-keep-fd=N` repeatable, if you ever need to intentionally pass extra fds

Doc wording (so it’s not “behavior change” drama):

* In `nc.1` and README under “Extensions”:

  * By default, when using exec modes, nc closes all file descriptors except stdin/stdout/stderr before executing the program. Disable with `--exec-inherit-fds`

---

## Constraints

* [x] IPv6 is optional via Meson feature and disabled by default
* [x] Remove IP_OPTIONS / LSRR and all source-routing flags/paths
* [x] Keep exec feature (dangerous) and keep TELNET negotiation
* [x] Replace `select()` + FD_SETSIZE hacks and `alarm/setjmp` timeouts with nonblocking + `poll()`
* [x] Replace `gethostbyname/gethostbyaddr/h_errno/res_init` with `getaddrinfo/getnameinfo`

---

## Original CLI compatibility backlog

* [x] Deliberately remove source-routing flags `-g`/`-G` (safety/portability)
* [ ] Document the deprecation clearly in:

  * [ ] README.md (compat notes)
  * [ ] nc.1 (options section)
  * [ ] `-h` help output

Legacy `-e` behavior must remain unchanged:

* [ ] `-e prog` execs `prog` with no args (no implicit shell)
* [ ] Exit code remains consistent with legacy expectations (127 on exec failure)

---

## 0) Project structure split

* [x] Create modules (even if you keep a single binary)

  * [x] `src/main.c` CLI + wiring
  * [x] `src/nc_ctx.h` / `src/nc_ctx.c` context struct + defaults
  * [x] `src/resolve.c` address resolution
  * [x] `src/connect.c` connect/listen helpers
  * [x] `src/io_pump.c` bidirectional copy loop using poll
  * [x] `src/telnet.c` TELNET negotiation helper
  * [x] `src/hexdump.c` optional traffic dump
  * [x] `src/exec.c` exec feature (gated, explicit warnings)

---

## 1) Meson: IPv6 optional feature, default disabled

* [x] Add a Meson feature option (default disabled)

  * [x] `meson_options.txt`

```meson
option('ipv6', type: 'feature', value: 'disabled', description: 'Enable IPv6 support')
```

* [x] In `meson.build`, detect headers and set a config define

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

* [x] In C, include config and guard IPv6 code

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

* [x] Remove:

  * [x] `-g`, `-G`, `gatesidx`, `gatesptr`, `gates` arrays
  * [x] `optbuf` source-routing builder
  * [x] any `#ifdef IP_OPTIONS` blocks
* [x] Update help text accordingly

---

## 3) Replace global variables with a single context struct

* [ ] Create `struct nc_ctx` and pass it everywhere

`src/nc_ctx.h` sketch:

```c
#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

enum nc_proto { NC_TCP, NC_UDP };

enum nc_exec_mode {
    NC_EXEC_NONE = 0,
    NC_EXEC_LEGACY_PROG,   // legacy -e prog, no args
    NC_EXEC_SH,            // new: --sh-exec
    NC_EXEC_ARGV,          // new: --exec-argv (execv)
};

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

    enum nc_exec_mode exec_mode;

    const char* exec_prog;
    char** exec_argv;

    bool exec_close_fds;      // default ON for exec
    bool exec_reset_signals;  // optional
};
```

* [ ] Replace `holler/bail` with modern logging helpers
* [ ] Ensure all logging goes to stderr by default and respects `-v` levels

---

## 4) Replace resolver code with getaddrinfo/getnameinfo

* [x] Remove:

  * [x] `gethostbyname`, `gethostbyaddr`, `h_errno`, `res_init`
  * [x] legacy resolver tables and host compare helpers

* [x] Implement:

  * [x] `nc_resolve_one()` using getaddrinfo
  * [x] reverse lookup using getnameinfo for verbose prints
  * [x] preserve legacy forward/reverse mismatch warning when `-v` and not `-n`

---

## 5) Connect timeout: remove alarm/setjmp and use nonblocking + poll

* [x] Delete `alarm`, signal(SIGALRM), setjmp/longjmp
* [x] Implement `nc_connect_with_timeout()` using O_NONBLOCK + poll() + SO_ERROR

---

## 6) Replace select()+FD_SETSIZE hacks with poll-based pump

* [x] Delete FD_SETSIZE redefines and select() paths
* [x] Implement a clean poll() pump loop
* [x] Reintroduce interval-per-line behavior in a controlled way
* [ ] Add `--pump=compat` only if a real compatibility regression is found

---

## 7) Telnet negotiation kept, but isolated

* [ ] Move TELNET logic into `src/telnet.c`
* [ ] Keep it pure and nonblocking
* [ ] Ensure behavior matches legacy `-t`
* [ ] Add a minimal regression test for telnet negotiation replies

---

## 8) Exec support: keep legacy, add new behaviors behind new options

Legacy behavior (must remain unchanged):

* [ ] `-e prog` runs `prog` directly with no args
* [ ] No implicit shell
* [ ] Exit 127 on exec failure
* [ ] Warn in `-h` output that it is dangerous (compat-friendly wording)

New options:

* [ ] `--exec-argv <prog> [args...]`

  * [ ] consumes remaining argv tokens as argv vector
  * [ ] uses `execv(prog, argv)`
* [ ] `--sh-exec <string>`

  * [ ] runs `/bin/sh -c <string>` explicitly
  * [ ] no change to `-e` semantics
* [ ] `--exec-inherit-fds`

  * [ ] disables default close-fds hardening
* [ ] `--exec-reset-signals`

  * [ ] resets signal handlers before exec
* [ ] Optional: `--exec-env-clear`

  * [ ] clears environment before exec

Exec implementation hardening:

* [ ] Check `dup2()` return values
* [ ] Don’t close netfd if it is 0/1/2
* [ ] Apply close-fds hardening by default unless `--exec-inherit-fds`
* [ ] Prefer `execv()` for argv mode
* [ ] Use `/bin/sh` only for sh mode

---

## 9) Remove “read argv from stdin” hack

* [x] Delete argc==1 stdin-argv behavior
* [ ] If needed later, add `--args-from-stdin` (opt-in)

---

## 10) Listening mode rework (TCP/UDP)

* [ ] Implement `nc_listen()` and `nc_accept()` for TCP
* [ ] UDP listen:

  * [ ] bind then lock to first peer by connect() after initial recvfrom/peek
  * [ ] preserve legacy behavior where observable

---

## 11) CLI/Help modernization

* [ ] Convert all K&R function definitions to ANSI prototypes
* [ ] Replace unsafe formatting and fixed buffers with snprintf
* [ ] Keep legacy flags and preserve behavior:

  * [ ] `-4` force IPv4
  * [ ] `-6` force IPv6 (error if ipv6 feature disabled)
  * [ ] `-l` listen
  * [ ] `-p` local port
  * [ ] `-s` local source address
  * [ ] `-u` UDP
  * [ ] `-v` verbose
  * [ ] `-n` numeric-only
  * [ ] `-w secs` timeout
  * [ ] `-i secs` interval
  * [ ] `-z` zero-IO scanning
  * [ ] `-t` telnet negotiation
  * [ ] `-o file` hexdump file
  * [ ] `-q secs` quit delay after stdin EOF
  * [ ] `-e prog` legacy exec

Add new options block (extensions):

* [ ] `--exec-argv`
* [ ] `--sh-exec`
* [ ] `--exec-inherit-fds`
* [ ] `--exec-reset-signals`

---

## 12) Hexdump: keep but modernize

* [ ] Ensure hexdump output remains compatible (prefixes, counters) if required
* [ ] Keep formatting bounded and fast
* [ ] Add `--hexdump-append` as a new option if append is desired
* [ ] Ensure hexdump fd is marked CLOEXEC unless explicitly required

---

## 13) Security and hardening toggles

Default low-level safety:

* [ ] Ensure all created fds use CLOEXEC by default
* [ ] Prefer `accept4(..., SOCK_CLOEXEC)` when available
* [ ] Avoid SIGPIPE surprises (MSG_NOSIGNAL or ignore SIGPIPE early)
* [ ] Poll loop EINTR correctness and robust POLLHUP/POLLERR handling

Optional build hardening (Meson options):

* [ ] `-fstack-protector-strong`
* [ ] `-fPIE -pie`
* [ ] `-Wl,-z,relro,-z,now`
* [ ] `_FORTIFY_SOURCE=2` when supported

---

## 14) Testing checklist

Core behavior:

* [ ] IPv4 TCP connect: `./nc host 80`
* [ ] IPv4 listen: `./nc -l -p 9999`
* [ ] UDP send/recv: `./nc -u host 9999`
* [ ] UDP listen + first peer lock: `./nc -u -l -p 9999`
* [ ] Telnet negotiation: verify `-t` responses
* [ ] Timeout: `-w 1` to a blackhole address returns ETIMEDOUT

Exec behavior:

* [ ] Legacy: `./nc -e /bin/cat host 9999`
* [ ] New argv exec: `./nc --exec-argv /bin/echo hello host 9999`
* [ ] New shell exec: `./nc --sh-exec 'id; uname -a' host 9999`
* [ ] Default hardening: without extra options, exec child inherits only 0/1/2
* [ ] Escape hatch: `--exec-inherit-fds` disables close-fds
* [ ] `-6` behavior:

  * [ ] ipv6 disabled: clear error
  * [ ] ipv6 enabled: connect/listen works

---

## 15) Cleanup list

* [ ] K&R function definitions (all)
* [x] FD_SETSIZE redefinition and select() paths
* [x] alarm, SIGALRM handler, setjmp/longjmp timeouts
* [ ] gethostbyname/gethostbyaddr/h_errno/res_init (after getaddrinfo migration)
* [x] include soup (netinet/in_systm.h, netinet/ip.h)
* [x] LSRR/IP_OPTIONS source routing (`-g`, `-G`, `gates*`)
* [x] argc==1 “read command line from stdin” hack
