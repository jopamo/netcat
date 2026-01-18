#include "pcap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/time.h>
#include <errno.h>

struct pcap_hdr_s {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct pcaprec_hdr_s {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

static FILE* pcap_fp = NULL;
static int pcap_fd = -1;
static int pcap_family = AF_UNSPEC;
static int pcap_socktype = SOCK_STREAM;
static struct sockaddr_storage local_addr, remote_addr;
static uint32_t seq_local = 1000, seq_remote = 2000;

void pcap_open(int fd, const char* path) {
    struct pcap_hdr_s hdr;
    socklen_t len;
    int type;

    if (!path)
        return;

    pcap_fp = fopen(path, "wb");
    if (!pcap_fp)
        return;

    pcap_fd = fd;
    hdr.magic_number = 0xa1b2c3d4;
    hdr.version_major = 2;
    hdr.version_minor = 4;
    hdr.thiszone = 0;
    hdr.sigfigs = 0;
    hdr.snaplen = 65535;
    hdr.network = 101; /* LINKTYPE_RAW (IP) */

    fwrite(&hdr, sizeof(hdr), 1, pcap_fp);

    len = sizeof(local_addr);
    getsockname(fd, (struct sockaddr*)&local_addr, &len);
    len = sizeof(remote_addr);
    getpeername(fd, (struct sockaddr*)&remote_addr, &len);
    pcap_family = local_addr.ss_family;

    len = sizeof(type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) == 0) {
        pcap_socktype = type;
    }
}

void pcap_log(int fd, const unsigned char* buf, size_t len, int direction) {
    struct pcaprec_hdr_s rec;
    struct timeval tv;
    unsigned char packet[65535];
    size_t offset = 0;
    uint16_t payload_len = (len > 65000) ? 65000 : len;

    if (!pcap_fp || fd != pcap_fd || pcap_family == AF_UNIX)
        return;

    gettimeofday(&tv, NULL);

    if (pcap_family == AF_INET) {
        struct iphdr* ip = (struct iphdr*)packet;
        memset(ip, 0, sizeof(struct iphdr));
        ip->version = 4;
        ip->ihl = 5;
        ip->ttl = 64;
        ip->protocol = (pcap_socktype == SOCK_STREAM) ? IPPROTO_TCP : IPPROTO_UDP;
        ip->saddr = (direction == 1) ? ((struct sockaddr_in*)&local_addr)->sin_addr.s_addr
                                     : ((struct sockaddr_in*)&remote_addr)->sin_addr.s_addr;
        ip->daddr = (direction == 1) ? ((struct sockaddr_in*)&remote_addr)->sin_addr.s_addr
                                     : ((struct sockaddr_in*)&local_addr)->sin_addr.s_addr;
        offset = sizeof(struct iphdr);

        if (pcap_socktype == SOCK_STREAM) {
            struct tcphdr* tcp = (struct tcphdr*)(packet + offset);
            memset(tcp, 0, sizeof(struct tcphdr));
            tcp->source = (direction == 1) ? ((struct sockaddr_in*)&local_addr)->sin_port
                                           : ((struct sockaddr_in*)&remote_addr)->sin_port;
            tcp->dest = (direction == 1) ? ((struct sockaddr_in*)&remote_addr)->sin_port
                                         : ((struct sockaddr_in*)&local_addr)->sin_port;
            tcp->seq = htonl((direction == 1) ? seq_local : seq_remote);
            tcp->ack_seq = htonl((direction == 1) ? seq_remote : seq_local);
            tcp->doff = 5;
            tcp->ack = 1;
            tcp->psh = 1;
            tcp->window = htons(65535);
            offset += sizeof(struct tcphdr);
            if (direction == 1)
                seq_local += payload_len;
            else
                seq_remote += payload_len;
        }
        else {
            struct udphdr* udp = (struct udphdr*)(packet + offset);
            memset(udp, 0, sizeof(struct udphdr));
            udp->source = (direction == 1) ? ((struct sockaddr_in*)&local_addr)->sin_port
                                           : ((struct sockaddr_in*)&remote_addr)->sin_port;
            udp->dest = (direction == 1) ? ((struct sockaddr_in*)&remote_addr)->sin_port
                                         : ((struct sockaddr_in*)&local_addr)->sin_port;
            udp->len = htons(sizeof(struct udphdr) + payload_len);
            offset += sizeof(struct udphdr);
        }
        ip->tot_len = htons(offset + payload_len);
    }
    else if (pcap_family == AF_INET6) {
        struct ip6_hdr* ip6 = (struct ip6_hdr*)packet;
        memset(ip6, 0, sizeof(struct ip6_hdr));
        ip6->ip6_vfc = 0x60;
        ip6->ip6_nxt = (pcap_socktype == SOCK_STREAM) ? IPPROTO_TCP : IPPROTO_UDP;
        ip6->ip6_hlim = 64;
        memcpy(&ip6->ip6_src,
               (direction == 1) ? &((struct sockaddr_in6*)&local_addr)->sin6_addr
                                : &((struct sockaddr_in6*)&remote_addr)->sin6_addr,
               16);
        memcpy(&ip6->ip6_dst,
               (direction == 1) ? &((struct sockaddr_in6*)&remote_addr)->sin6_addr
                                : &((struct sockaddr_in6*)&local_addr)->sin6_addr,
               16);
        offset = sizeof(struct ip6_hdr);

        if (pcap_socktype == SOCK_STREAM) {
            struct tcphdr* tcp = (struct tcphdr*)(packet + offset);
            memset(tcp, 0, sizeof(struct tcphdr));
            tcp->source = (direction == 1) ? ((struct sockaddr_in6*)&local_addr)->sin6_port
                                           : ((struct sockaddr_in6*)&remote_addr)->sin6_port;
            tcp->dest = (direction == 1) ? ((struct sockaddr_in6*)&remote_addr)->sin6_port
                                         : ((struct sockaddr_in6*)&local_addr)->sin6_port;
            tcp->seq = htonl((direction == 1) ? seq_local : seq_remote);
            tcp->ack_seq = htonl((direction == 1) ? seq_remote : seq_local);
            tcp->doff = 5;
            tcp->ack = 1;
            tcp->psh = 1;
            tcp->window = htons(65535);
            offset += sizeof(struct tcphdr);
            if (direction == 1)
                seq_local += payload_len;
            else
                seq_remote += payload_len;
        }
        else {
            struct udphdr* udp = (struct udphdr*)(packet + offset);
            memset(udp, 0, sizeof(struct udphdr));
            udp->source = (direction == 1) ? ((struct sockaddr_in6*)&local_addr)->sin6_port
                                           : ((struct sockaddr_in6*)&remote_addr)->sin6_port;
            udp->dest = (direction == 1) ? ((struct sockaddr_in6*)&remote_addr)->sin6_port
                                         : ((struct sockaddr_in6*)&local_addr)->sin6_port;
            udp->len = htons(sizeof(struct udphdr) + payload_len);
            offset += sizeof(struct udphdr);
        }
        ip6->ip6_plen = htons(offset - sizeof(struct ip6_hdr) + payload_len);
    }
    else {
        return; /* Unsupported family for PCAP */
    }

    memcpy(packet + offset, buf, payload_len);

    rec.ts_sec = tv.tv_sec;
    rec.ts_usec = tv.tv_usec;
    rec.incl_len = offset + payload_len;
    rec.orig_len = offset + payload_len;

    fwrite(&rec, sizeof(rec), 1, pcap_fp);
    fwrite(packet, offset + payload_len, 1, pcap_fp);
    fflush(pcap_fp);
}

void pcap_close(void) {
    if (pcap_fp) {
        fclose(pcap_fp);
        pcap_fp = NULL;
        pcap_fd = -1;
    }
}
