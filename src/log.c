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
    fprintf(stderr, "Netcat 30th anniversary edition\n");
    fprintf(stderr,
            "\n"
            "        /\\_/\\\n"
            "       / 0 0 \\\n"
            "      ====v====\n"
            "       \\  W  /\n"
            "       |     |     _\n"
            "       / ___ \\    /\n"
            "      / /   \\ \\  |\n"
            "     (((-----)))-'\n"
            "      /\n"
            "     (      ___\n"
            "      \\__.=|___E\n"
            "             /\n"
            "\n");
    fprintf(stderr,
            "\n"
            "Usage: nc [options] [destination] [port]\n"
            "\n"
            "Options taking a time assume seconds.\n"
            "\n"
            "  -4                         Use IPv4 only\n"
            "  -6                         Use IPv6 only\n"
            "  -U                         Use UNIX domain socket\n"
            "      --vsock <cid:port>     Use vsock sockets only\n"
            "  -l                         Listen mode, for inbound connects\n"
            "      --keep-open            Accept multiple connections in listen mode\n"
            "  -u                         UDP mode\n"
            "  -c                         Use TLS\n"
            "  -C <certfile>              Public key file\n"
            "  -K <keyfile>               Private key file\n"
            "  -R <CAfile>                CA bundle\n"
            "  -e <name>                  Required name in peer certificate\n"
            "  -H <hash>                  Required hash of peer certificate\n"
            "  -o <file>                  OCSP stapling file\n"
            "  -Z <file>                  Save peer certificate (use \"-\" for stderr)\n"
            "  -n                         Suppress name/port resolutions\n"
            "  -v                         Verbose\n"
            "  -z                         Zero-I/O mode (scan)\n"
            "  -N                         Shutdown network socket after EOF on stdin\n"
            "  -d                         Detach from stdin\n"
            "  -F                         Pass socket fd to stdout and exit\n"
            "  -j                         JSON output\n"
            "  -i <interval>              Delay between read/write polls\n"
            "      --jitter <seconds>     Add Gaussian-distributed random delay to -i\n"
            "  -w <timeout>               Connect timeout and final net reads\n"
            "  -W <recvlimit>             Terminate after receiving N packets\n"
            "  -p <port>                  Specify local source port\n"
            "  -s <addr>                  Source address\n"
            "  -r                         Randomize remote ports\n"
            "  -M <ttl>                   Set IP TTL / IPv6 hops\n"
            "  -m <minttl>                Set IP minimum TTL / hopcount\n"
            "  -T <keyword|value>         IP TOS/TCLASS or TLS option\n"
            "  -I <length>                TCP receive buffer size\n"
            "  -O <length>                TCP send buffer size\n"
            "  -x <addr[:port]>           Proxy address and port\n"
            "  -X <proto>                 Proxy protocol: \"5\" (SOCKS) or \"connect\"\n"
            "  -P <proxyuser>             Proxy authentication username\n"
            "      --proxy-proto          Expect PROXY protocol v2 header\n"
            "      --send-proxy           Send PROXY protocol v2 header\n"
            "      --pcap <file>          Write a PCAP capture\n"
            "      --hex-dump <file>      Dump session data as hex\n"
            "      --bpf-prog <file>      Attach BPF program to socket\n"
            "      --bpf-evasion <file>   Load eBPF program to hide process artifacts\n"
            "      --xdp-stealth <iface>  Load XDP program for invisible networking\n"
            "      --mptcp                Enable Multipath TCP\n"
            "      --tfo                  Enable TCP Fast Open\n"
            "      --mark <mark>          Set SO_MARK\n"
            "      --interface <iface>    Bind socket to device\n"
            "      --transparent          Enable IP_TRANSPARENT\n"
            "      --namespace <path>     Network namespace path\n"
            "      --splice               Use zero-copy splice loop\n"
            "      --io-uring             Use io_uring (if available)\n"
            "      --fuzz-tcp             Send random TCP data\n"
            "      --fuzz-udp             Send random UDP data\n"
            "      --quic                 QUIC probe (UDP)\n"
            "      --quic-mask            Pad UDP packets to ~1350 bytes\n"
            "      --profile <type>       Malleable profile: html, css, base64-json,\n"
            "                             json-dialect, xor-mask\n"
            "      --version              Show version information\n"
            "  -h, --help                 Display this help screen\n"
            "\n");
    exit(1);
}

void usage(int ret) {
    fprintf(stderr,
            "usage: nc [-46cDdFhklNnruUvz] [-C certfile] [-e name] "
            "[-H hash] [-I length]\n"
            "\t  [-i interval] [--jitter s] [-K keyfile] [-M ttl] [-m minttl] [-O length]\n"
            "\t  [--profile type] [--quic-mask] [-P proxy_username] [-p source_port]\n"
            "\t  [-R CAfile] [-s sourceaddr] [-T keyword] [-W recvlimit]\n"
            "\t  [-w timeout] [-X proxy_protocol] [-x proxy_address[:port]]\n"
            "\t  [--bpf-evasion file] [--xdp-stealth iface] [--version]\n"
            "\t  [destination] [port]\n");
    if (ret)
        exit(1);
}
