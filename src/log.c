#include "netcat.h"
#ifdef __linux__
#include <linux/vm_sockets.h>
#endif

void report_sock(const char* msg, const struct sockaddr* sa, socklen_t salen, char* path) {
    char host[NI_MAXHOST], port[NI_MAXSERV];
    int herr;
    int flags = NI_NUMERICSERV;
    char tbuf[32];
    time_t now;
    struct tm* tm_info;

    if (jflag) {
        time(&now);
        tm_info = gmtime(&now);
        strftime(tbuf, sizeof(tbuf), "%Y-%m-%dT%H:%M:%SZ", tm_info);
    }

    if (path != NULL) {
        if (jflag) {
            fprintf(stderr, "{\"timestamp\":\"%s\",\"level\":\"info\",\"event\":\"%s\",\"path\":\"%s\"}\n", tbuf, msg,
                    path);
        }
        else {
            fprintf(stderr, "%s on %s\n", msg, path);
        }
        return;
    }

    if (nflag)
        flags |= NI_NUMERICHOST;

#ifdef __linux__
    if (sa && sa->sa_family == AF_VSOCK) {
        struct sockaddr_vm* svm = (struct sockaddr_vm*)sa;
        if (jflag) {
            fprintf(stderr, "{\"timestamp\":\"%s\",\"level\":\"info\",\"event\":\"%s\",\"cid\":%u,\"port\":%u}\n", tbuf,
                    msg, svm->svm_cid, svm->svm_port);
        }
        else {
            fprintf(stderr, "%s on vsock:%u:%u\n", msg, svm->svm_cid, svm->svm_port);
        }
        return;
    }
#endif

    herr = getnameinfo(sa, salen, host, sizeof(host), port, sizeof(port), flags);
    switch (herr) {
        case 0:
            break;
        case EAI_SYSTEM:
            err(1, "getnameinfo");
        default:
            errx(1, "getnameinfo: %s", gai_strerror(herr));
    }

    if (jflag) {
        fprintf(stderr, "{\"timestamp\":\"%s\",\"level\":\"info\",\"event\":\"%s\",\"host\":\"%s\",\"port\":\"%s\"}\n",
                tbuf, msg, host, port);
    }
    else {
        fprintf(stderr, "%s on %s %s\n", msg, host, port);
    }
}

void help(void) {
    usage(0);
    fprintf(stderr,
            "\n\tGeneral Options:\n"
            "\t-4\t\tUse IPv4\n"
            "\t-6\t\tUse IPv6\n"
            "\t-d\t\tDetach from stdin\n"
            "\t-h, --help\tThis help text\n"
            "\t-k\t\tKeep inbound sockets open for multiple connects\n"
            "\t-l\t\tListen mode, for inbound connects\n"
            "\t-N\t\tShutdown the network socket after EOF on stdin\n"
            "\t-n\t\tSuppress name/port resolutions\n"
            "\t-p port\t\tSpecify local port for remote connects\n"
            "\t-r\t\tRandomize remote ports\n"
            "\t-U\t\tUse UNIX domain socket\n"
            "\t-u\t\tUDP mode\n"
            "\t-v\t\tVerbose\n"
            "\t-z\t\tZero-I/O mode [used for scanning]\n"
            "\n"
            "\tEvasion & Stealth:\n"
            "\t--bpf-evasion <file>\tLoad eBPF program to hide process artifacts (e.g. from ps)\n"
            "\t--xdp-stealth <iface>\tLoad XDP program for invisible networking (requires --bpf-prog)\n"
            "\t\t\t\tDrops magic packets from kernel stack but processes payload.\n"
            "\t(Indirect Syscalls)\tAutomatically active on x86_64/ARM64 to bypass user-land hooks.\n"
            "\n"
            "\tTraffic Shaping & Mimicry:\n"
            "\t--jitter <seconds>\tAdd Gaussian-distributed random delay to -i interval\n"
            "\t\t\t\tUses Box-Muller transform for organic burstiness.\n"
            "\t--profile <type>\tApply Malleable Profile to traffic:\n"
            "\t\t\t\thtml         : Wrap in HTML comments <!-- ... -->\n"
            "\t\t\t\tcss          : Wrap in CSS comments /* ... */\n"
            "\t\t\t\tbase64-json  : Base64 in JSON {\"status\":\"success\"...}\n"
            "\t\t\t\tjson-dialect : Randomized JSON telemetry reports\n"
            "\t\t\t\txor-mask     : Rolling XOR (Key: DEADBEEF)\n"
            "\t--quic-mask\t\tPad UDP packets to ~1350 bytes (Video Stream mimicry)\n"
            "\n"
            "\tNetwork Options:\n"
            "\t-C certfile\tPublic key file\n"
            "\t-c\t\tUse TLS\n"
            "\t-e name\t\tRequired name in peer certificate\n"
            "\t-K keyfile\tPrivate key file\n"
            "\t-P proxyuser\tUsername for proxy authentication\n"
            "\t-R CAfile\tCA bundle\n"
            "\t-w timeout\tTimeout for connects and final net reads\n"
            "\t-X proto\tProxy protocol: \"5\" (SOCKS) or \"connect\"\n"
            "\t-x addr[:port]\tSpecify proxy address and port\n"
            "\t--proxy-proto\tExpect PROXY protocol v2 header\n"
            "\n");
    exit(1);
}

void usage(int ret) {
    fprintf(stderr,
            "usage: nc [-46cDdFhklNnruUvz] [-C certfile] [-e name] "
            "[-H hash] [-I length]\n"
            "\t  [-i interval] [--jitter s] [-K keyfile] [-M ttl] [-m minttl] [-O length]\n"
            "\t  [--profile type] [--quic-mask] [-P proxy_username] [-p source_port]\n"
            "\t  [-R CAfile] [-s sourceaddr] [-T keyword] [-V rtable] [-W recvlimit]\n"
            "\t  [-w timeout] [-X proxy_protocol] [-x proxy_address[:port]]\n"
            "\t  [--bpf-evasion file] [--xdp-stealth iface]\n"
            "\t  [destination] [port]\n");
    if (ret)
        exit(1);
}
