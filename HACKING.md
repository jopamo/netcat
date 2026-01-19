# Hacking on Netcat 2.0

Welcome to the development guide for Netcat 2.0. This modern iteration transforms the classic tool into a high-performance, stealth-capable network utility using advanced Linux features like `io_uring` and `eBPF`.

## 1. Build System & Dependencies

We use **Meson** and **Ninja** for a fast, reliable build process.

*   **Setup:** `meson setup build`
*   **Compile:** `meson compile -C build`
*   **Test:** `meson test -C build`
*   **Clean:** `meson setup --wipe build`

**Key Dependencies:**
*   `liburing` (optional, for `-U` mode)
*   `libbpf` (required for evasion features)
*   `libssl` / `libcrypto` (for TLS)

## 2. Project Structure

The codebase is modularized to separate core logic from the new offensive capabilities.

*   **`src/netcat.c`**: The main entry point. Handles argument parsing (`getopt_long`) and high-level connection setup.
*   **`src/io.c`**: The heart of the data transfer. Contains the `readwrite` loop, **Foliage Sleep** logic, **Traffic Shaping** (Jitter), and **Malleable Profiles** (in `drainbuf`).
*   **`src/syscalls.h`**: The **Stealth Layer**. Contains the `find_gadget` logic and inline assembly for **Indirect Syscalls** (Trampolines).
*   **`src/bpf.c`**: Loader logic for eBPF programs. Handles attaching XDP programs and Tracepoints.
*   **`src/*.bpf.c`**: Source code for the kernel-side eBPF programs (e.g., `bpf_xdp.bpf.c` for Ghost Mode).
*   **`tests/`**: Python-based integration tests.

## 3. Developing Evasion Features

If you are contributing to the "Red Team" features, adhere to these guidelines:

### Indirect Syscalls (`src/syscalls.h`)
*   **Goal:** Never execute a `syscall` instruction directly from our text segment.
*   **Mechanism:** We find gadgets (`syscall`, `ret`) inside `libc` at runtime.
*   **Adding a Syscall:** If you need a new syscall (e.g., `sendto`), add a `direct_sendto` wrapper in `syscalls.h` that uses the `call *%reg` pattern (Level 2/3) and falls back to `syscall` (Level 1) if gadgets aren't found.

### Traffic Shaping (`src/io.c`)
*   **Jitter:** The `readwrite` loop uses `gaussian_random` to determine sleep times.
*   **Profiles:** Transformations happen in `drainbuf`. To add a new profile (e.g., `xml-soap`):
    1.  Add a string check: `if (strcmp(profile, "xml-soap") == 0) ...`
    2.  Implement the transformation (encode `buf` into `temp_buf`).
    3.  Ensure you handle the buffer lengths correctly so the main loop state remains consistent.

### eBPF & XDP
*   **Kernel Side:** Write your eBPF C code in `src/`. Do *not* include standard userspace headers. Use `vmlinux.h` or specific kernel headers.
*   **User Side:** Add a loader function in `src/bpf.c` using `libbpf` APIs (`bpf_object__open`, `bpf_program__attach`).
*   **Hooking:** Add a flag in `src/netcat.c` to trigger the loader.

## 4. Code Style & Safety

*   **Style:** We generally follow **OpenBSD KNF**, but with modern C allowances.
*   **Formatting:** Run `clang-format -i src/*.c src/*.h` before submitting.
*   **Memory:** We use `posix_memalign` for main buffers to support `mprotect` tricks. Always ensure aligned pointers if you plan to change memory permissions.
*   **Strings:** Use `strlcpy` / `strlcat`. Never use `strcpy`.

## 5. Testing

*   **Unit Tests:** Add python scripts in `tests/`.
*   **Sanitizers:** The build is configured with AddressSanitizer (ASAN) and UndefinedBehaviorSanitizer (UBSAN) by default in debug mode. Ensure your code does not leak memory or invoke undefined behavior (like unaligned access).

Happy Hacking!
