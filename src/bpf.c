#include "netcat.h"
#include "bpf.h"

#ifdef HAVE_LIBBPF
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>

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
            /* Don't return -1 immediately, try other programs or just warn? */
            bpf_object__close(obj);
            return -1;
        }
    }

    return 0;
}

/* Perf buffer callback */
static void handle_event(void* ctx, int cpu, void* data, __u32 data_sz) {
    (void)ctx;
    (void)cpu;
    unsigned char* payload = data;

    /* We expect "NCXDP" + Command */
    /* Check bounds just in case */
    if (data_sz <= 5)
        return;

    /* Print the command to stdout (or execute it) */
    /* Format: NCXDP<command> */
    char* cmd = (char*)(payload + 5);
    int cmd_len = data_sz - 5;

    fprintf(stdout, "Stealth Command Received: %.*s\n", cmd_len, cmd);
}

int load_xdp_stealth(const char* prog_path, const char* interface) {
    struct bpf_object* obj;
    struct bpf_program* prog;
    struct perf_buffer* pb = NULL;
    int ifindex;
    int err;

    ifindex = if_nametoindex(interface);
    if (!ifindex) {
        warnx("Invalid interface: %s", interface);
        return -1;
    }

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

    /* Find the XDP program */
    prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        warnx("No BPF program found");
        bpf_object__close(obj);
        return -1;
    }

    /* Attach XDP to interface */
    struct bpf_link* link = bpf_program__attach_xdp(prog, ifindex);
    if (libbpf_get_error(link)) {
        warnx("Failed to attach XDP to %s", interface);
        bpf_object__close(obj);
        return -1;
    }

    fprintf(stderr, "XDP Stealth Mode Active on %s. Waiting for Magic Packets...\n", interface);

    /* Setup Perf Buffer */
    int map_fd = bpf_object__find_map_fd_by_name(obj, "perf_map");
    if (map_fd < 0) {
        warnx("Could not find perf_map");
        return -1;
    }

    pb = perf_buffer__new(map_fd, 8, handle_event, NULL, NULL, NULL);
    if (libbpf_get_error(pb)) {
        warnx("Failed to create perf buffer");
        return -1;
    }

    /* Poll loop */
    while (1) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            warnx("Error polling perf buffer: %d", err);
            break;
        }
    }

    perf_buffer__free(pb);
    bpf_object__close(obj);
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

int load_xdp_stealth(const char* prog_path, const char* interface) {
    (void)prog_path;
    (void)interface;
    warnx("eBPF support not compiled in (missing libbpf)");
    return -1;
}

#endif