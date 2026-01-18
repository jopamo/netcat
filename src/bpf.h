#ifndef BPF_H
#define BPF_H

#include "netcat.h"

int attach_bpf_prog(int s, const char* prog_path);

#endif /* BPF_H */
