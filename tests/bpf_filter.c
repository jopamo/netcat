#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("socket")
int filter_drop(struct __sk_buff* skb) {
    return 0; /* Drop everything (pass 0 bytes) */
}

char _license[] SEC("license") = "GPL";
