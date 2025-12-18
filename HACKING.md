# HACKING

## Development Setup

- Requirements: C17 toolchain, Meson, Ninja, and standard libc headers. `pkg-config` helps Meson discover optional libraries like `libresolv` or `libm`.
- Clone the repo and run commands from the project root. Meson writes `config.h`, so rebuild after changing feature flags.
- Feature toggles:
  - `-Dipv6=enabled|disabled|auto` (default: disabled)
  - `-Dtelnet=true|false` (default: true)
  - `-Dverbose_debug=true|false` (default: false)
  - `-Dexec_hole=true|false` (default: false; enables the dangerous `-e`/`-c` exec support)
- `nc` is built from the modular sources in `src/` and is the installed binary.

## Build and Test

```sh
# Configure (re-run with --reconfigure to change options)
meson setup build -Dipv6=disabled -Dtelnet=true -Dexec_hole=false

# Build both binaries
meson compile -C build

# Optional install of the classic nc and scripts/man page
meson install -C build

# Smoke-test the binaries
./build/nc -h
./build/nc example.com 80

# Automated tests are not yet present; rely on manual checks above.
```

## Coding Standards

- Language: C17 (`c_std=c17` in Meson). Prefer the Meson build over ad-hoc Makefiles.
- Follow `.clang-format` for style; keep new code warning-clean under the current `warning_level=3`.
- Use the `nc_ctx` helpers for logging/errors (`nc_holler`, `nc_bail`) instead of raw `printf`.
- Keep networking code on the modern path (`getaddrinfo`, nonblocking connect with `poll`); avoid reintroducing removed source-routing or legacy resolver APIs.
- Default to ASCII text in code and docs unless existing content already uses other characters.

## Contribution Flow

- Create a branch, make targeted changes, and keep commits focused.
- Run `meson compile -C build` (and `meson test -C build` if tests are added) before submitting.
- Update `DESIGN.md` for architectural changes and `README.md`/`TODO.md` for user-facing or backlog updates as needed.
- Open a pull request with a brief summary of behavior changes and any feature flags required for validation.
