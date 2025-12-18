# TODO.md — Fork/rewrite Netcat

## Goal

Rework the K&R-era netcat-like implementation into modern, maintainable C11 while preserving original CLI options and behavior by default, while improving low-level safety, robustness, and auditability

This project intentionally remains a **raw transport tool**
Security is provided *around* nc, not *inside* it

---

## Non-goals (by design)

These are explicit and intentional constraints

- No built-in encryption, authentication, certificates, or key management (TLS/SSH/etc)
- No protocol framing beyond legacy behavior
- No claims of “secure transport” in code, docs, or help output
- No silent behavior changes that imply safety guarantees
- Prefer documentation and integration guidance over reimplementing security tools

Netcat remains a byte pump
Security belongs in ssh, socat, TLS wrappers, or the surrounding system

---

## Compatibility policy

- Legacy flags keep exact semantics (including edge cases) unless explicitly documented as deprecated
- Name resolution behavior remains unchanged by default (`-n` retains numeric-only semantics)
- New behavior is introduced only behind new options (prefer long options to avoid collisions)
- Internal hardening defaults are allowed when they do **not** change flag meaning or user-visible I/O semantics
- Raw I/O contract remains: bytes in → bytes out

---

## Exec hygiene default: close fds in child

Default behavior improves hygiene without changing `-e` semantics

- When exec modes are used, child inherits only fd 0/1/2 by default
- Prevents accidental leakage of sockets, logs, hexdump files, etc
- This is an internal hardening default, not a new security feature

Escape hatch (new option)

- `--exec-inherit-fds` disables close-fds behavior

Policy

- `-e` behavior remains unchanged
- Only the child environment is hardened
- Users relying on inherited fds can explicitly opt out

Implementation shape

Context default

```c
ctx->exec_close_fds = true; // default ON
````

CLI parsing

* `--exec-inherit-fds` → `ctx->exec_close_fds = false`

Exec path

* `dup2(netfd, 0/1/2)` with return-value checks
* Close original `netfd` if > 2
* If `exec_close_fds` is enabled, close all fds ≥ 3
* Execute program

Preferred implementation

```c
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>

static void nc_close_fds_keep_stdio(void) {
#if defined(__linux__) && defined(SYS_close_range)
    if (syscall(SYS_close_range, 3U, ~0U, 0U) == 0)
        return;
#endif
    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0)
        maxfd = 1024;
    for (long fd = 3; fd < maxfd; fd++)
        close((int)fd);
}
```

---

## Low-level robustness improvements (default)

These preserve option semantics but improve correctness

* Mark all non-stdio fds CLOEXEC by default

  * sockets
  * hexdump files
  * logs
  * temp files

* Avoid SIGPIPE surprises

  * Prefer `send(..., MSG_NOSIGNAL)` when available
  * Avoid global SIGPIPE behavior changes that alter exit semantics

* Poll loop correctness

  * Retry `poll/read/write` on EINTR
  * Handle POLLHUP and POLLERR explicitly
  * No busy loops

* Testing gaps

  * Randomized port selection (-r) needs deterministic seeding hook for reliable CLI coverage

* Accept hygiene

  * Prefer `accept4(..., SOCK_CLOEXEC)` when available
  * Fallback to `accept` + `fcntl(FD_CLOEXEC)`

* Nonblocking connect done correctly

  * `O_NONBLOCK + poll + getsockopt(SO_ERROR)`

---

## Constraints (locked in)

* IPv6 is optional via Meson feature and disabled by default
* IP_OPTIONS / LSRR and all source-routing paths are removed
* Exec feature remains available but dangerous by nature
* TELNET negotiation remains supported
* Replace `select()` + FD_SETSIZE hacks with nonblocking + poll
* Replace `alarm/setjmp` timeouts with poll-based timeouts
* Replace legacy resolver APIs with `getaddrinfo/getnameinfo`

---

## Original CLI compatibility backlog

* Deliberately remove source-routing flags `-g` / `-G`
* Clearly document deprecation in (done)

  * README.md
  * nc.1
  * `-h` output

Legacy `-e` behavior must remain unchanged

* `-e prog` execs `prog` directly, no implicit shell
* Exit code 127 on exec failure
* No argument parsing changes

---

## Project structure split

Create modules even if output remains a single binary

* `src/main.c` CLI parsing and wiring
* `src/nc_ctx.h` / `src/nc_ctx.c` context struct and defaults
* `src/resolve.c` address resolution
* `src/connect.c` connect/listen helpers
* `src/io_pump.c` bidirectional poll-based pump
* `src/telnet.c` TELNET negotiation
* `src/hexdump.c` traffic dump support
* `src/exec.c` exec logic (explicit, gated, warned)

---

## Meson: feature gating

IPv6 option (default disabled)

```meson
option('ipv6', type: 'feature', value: 'disabled',
       description: 'Enable IPv6 support')
```

Exec option (default disabled)

```meson
option('exec', type: 'boolean', value: false,
       description: 'Enable dangerous exec (-e) support')
```

Behavior when disabled

* `-e` prints a clear error and exits nonzero

---

## Resolver modernization

* Remove `gethostbyname`, `gethostbyaddr`, `h_errno`, `res_init`
* Implement `nc_resolve_one()` using `getaddrinfo`
* Reverse lookup via `getnameinfo` for verbose output
* Preserve legacy forward/reverse mismatch warnings when `-v` and not `-n`

---

## Connect timeout rework

* Remove `alarm`, SIGALRM, `setjmp/longjmp`
* Implement nonblocking connect with poll + SO_ERROR

---

## Poll-based I/O pump

* Replace all select() paths
* Remove FD_SETSIZE hacks
* Clean poll loop with explicit states
* Reintroduce interval-per-line behavior without global sleeps
* Add `--pump=compat` only if real regressions appear

---

## TELNET support

* Move TELNET logic into `src/telnet.c`
* Nonblocking, isolated logic
* Preserve `-t` behavior
* Add minimal regression test for negotiation replies

---

## Exec support

Legacy behavior (unchanged)

* `-e prog` runs prog directly
* No implicit shell
* Exit 127 on exec failure

New options (extensions)

* `--exec-argv <prog> [args...]`

  * Uses `execv`
* `--sh-exec <string>`

  * Explicit `/bin/sh -c`
* `--exec-inherit-fds`

  * Disable close-fds hygiene
* `--exec-reset-signals`

  * Reset signal handlers before exec
* Optional future

  * `--exec-env-clear`

Exec implementation requirements

* Check all `dup2()` return values
* Do not close netfd if it is 0/1/2
* Close extra fds by default
* Prefer `execv`
* Use `/bin/sh` only in sh mode

---

## Remove stdin argv hack

* Delete argc==1 “read argv from stdin” behavior
* Optional future: `--args-from-stdin` (explicit opt-in)

---

## Listening mode rework

TCP

* Clean `nc_listen()` and `nc_accept()`

UDP

* Bind
* Receive initial datagram
* Lock peer using `connect()`
* Preserve legacy observable behavior

---

## CLI and help cleanup

* Convert all K&R definitions to ANSI C
* Replace unsafe formatting with snprintf
* Preserve all legacy flags and behavior
* Add “Extensions” section for new options
* Clearly warn that exec is dangerous without implying security guarantees

---

## Hexdump

* Preserve legacy formatting
* Keep fast and bounded
* Mark hexdump fd CLOEXEC
* Optional new option: `--hexdump-append`

---

## Hardening defaults

* CLOEXEC everywhere by default
* `accept4(..., SOCK_CLOEXEC)` when available
* SIGPIPE-safe send paths
* Poll loop EINTR correctness

Optional build hardening (Meson)

* `-fstack-protector-strong`
* `-fPIE -pie`
* `-Wl,-z,relro,-z,now`
* `_FORTIFY_SOURCE=2` when supported

---

## Testing checklist

Core

* IPv4 TCP connect
* IPv4 listen
* UDP send/recv
* UDP listen + peer lock
* TELNET negotiation
* Poll-based timeout behavior

Exec

* Legacy `-e`
* `--exec-argv`
* `--sh-exec`
* Default close-fds hygiene
* Escape hatch `--exec-inherit-fds`

IPv6

* Disabled: clear error on `-6`
* Enabled: connect/listen works

---

## Cleanup list

* K&R function definitions
* FD_SETSIZE hacks
* alarm / SIGALRM paths
* legacy resolver APIs
* source routing flags and code
* argc==1 stdin argv hack
