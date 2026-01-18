#include "netcat.h"
#include "bpf.h"

#ifdef HAVE_LIBBPF
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <fcntl.h>

int attach_bpf_prog(int s, const char* prog_path) {
    struct bpf_object* obj;
    struct bpf_program* prog;
    int prog_fd;
    int err;

    /* Load the BPF object file */
    obj = bpf_object__open_file(prog_path, NULL);
    if (libbpf_get_error(obj)) {
        warnx("bpf_object__open_file failed: %s", prog_path);
        return -1;
    }

    /* Load the programs */
    err = bpf_object__load(obj);
    if (err) {
        warnx("bpf_object__load failed: %s", strerror(-err));
        bpf_object__close(obj);
        return -1;
    }

    /* Find the first program in the object */
    /* Usually filter programs are named specifically, but we take the first one or assume there's one. */
    prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        warnx("No BPF program found in object file");
        bpf_object__close(obj);
        return -1;
    }

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        warnx("Failed to get BPF program FD");
        bpf_object__close(obj);
        return -1;
    }

    /* Attach to socket */
    if (setsockopt(s, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) < 0) {
        warn("setsockopt(SO_ATTACH_BPF) failed");
        bpf_object__close(obj);
        return -1;
    }

    /*
     * Note: The BPF object/program needs to stay loaded as long as the socket is open?
     * With SO_ATTACH_BPF, the kernel takes a reference to the program.
     * So we can close the userspace object if we want, or keep it.
     * "When the file descriptor is closed, the reference count is decremented."
     * Wait, prog_fd is a file descriptor. If we close prog_fd (via bpf_object__close),
     * does the kernel keep the program if attached to a socket?
     * Yes, SO_ATTACH_BPF takes a reference to the program.
     *
     * However, libbpf manages the lifetime.
     * We should verify if bpf_object__close closes the FD. It does.
     */

    /* We can close the object now, kernel has ref. */
    /* Actually, verify this. */
    /* "The program is kept alive as long as it is attached to a socket." */

    /* To be safe, we might leak the object structure if we are short lived, but
       we are a CLI tool, so we can just let it leak or close it.
       If we close it, prog_fd is closed.
    */
    /* bpf_object__close(obj); */

    return 0;
}

int load_bpf_tracepoint(const char* prog_path) {
    struct bpf_object* obj;
    struct bpf_link* link;
    struct bpf_program* prog;
    int err;

    /* Load the BPF object file */
    obj = bpf_object__open_file(prog_path, NULL);
    if (libbpf_get_error(obj)) {
        warnx("bpf_object__open_file failed: %s", prog_path);
        return -1;
    }

    /* Load the programs */
    err = bpf_object__load(obj);
    if (err) {
        warnx("bpf_object__load failed: %s", strerror(-err));
        bpf_object__close(obj);
        return -1;
    }

    /* Iterate over all programs and attach them */
    bpf_object__for_each_program(prog, obj) {
        link = bpf_program__attach(prog);
        if (libbpf_get_error(link)) {
            warnx("bpf_program__attach failed");
            link = NULL;
            /* Don't return -1 immediately, try other programs or just warn? */
            /* Usually strictly failing is better for this tool */
            bpf_object__close(obj);
            return -1;
        }
    }

    /* Keep the object loaded.
       For tracepoints via bpf_link, we need to keep the link and object alive.
       Since netcat is a long-running process (potentially), we just leak the reference
       or store it globally if we wanted to detach on exit.
       For now, we let it persist until process exit.
    */

    return 0;
}

#else

int attach_bpf_prog(int s, const char* prog_path) {
    (void)s;
    (void)prog_path;
    warnx("eBPF support not compiled in (missing libbpf)");
    return -1;
}

int load_bpf_tracepoint(const char* prog_path) {
    (void)prog_path;
    warnx("eBPF support not compiled in (missing libbpf)");
    return -1;
}

#endif
