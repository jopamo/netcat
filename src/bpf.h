#ifndef BPF_H
#define BPF_H

#include "netcat.h"

int attach_bpf_prog(int s, const char* prog_path);
int load_bpf_tracepoint(const char* prog_path);
int load_xdp_stealth(const char* prog_path, const char* interface);

#endif /* BPF_H */
