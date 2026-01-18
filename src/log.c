#include "netcat.h"

void report_sock(const char* msg, const struct sockaddr* sa, socklen_t salen, char* path) {
    char host[NI_MAXHOST], port[NI_MAXSERV];
    int herr;
    int flags = NI_NUMERICSERV;

    if (path != NULL) {
        fprintf(stderr, "%s on %s\n", msg, path);
        return;
    }

    if (nflag)
        flags |= NI_NUMERICHOST;

    herr = getnameinfo(sa, salen, host, sizeof(host), port, sizeof(port), flags);
    switch (herr) {
        case 0:
            break;
        case EAI_SYSTEM:
            err(1, "getnameinfo");
        default:
            errx(1, "getnameinfo: %s", gai_strerror(herr));
    }

    fprintf(stderr, "%s on %s %s\n", msg, host, port);
}

void help(void) {
    usage(0);
    fprintf(
        stderr,
        "\tCommand Summary:\n\t-4\t\tUse IPv4\n\t-6\t\tUse IPv6\n\t-C certfile\tPublic key file\n\t-c\t\tUse "
        "TLS\n\t-D\t\tEnable the debug socket option\n\t-d\t\tDetach from stdin\n\t-e name\t\tRequired name in peer "
        "certificate\n\t-F\t\tPass socket fd\n\t-H hash\t\tHash string of peer certificate\n\t-h\t\tThis help "
        "text\n\t-I length\tTCP receive buffer length\n\t-i interval\tDelay interval for lines sent, ports "
        "scanned\n\t-K keyfile\tPrivate key file\n\t-k\t\tKeep inbound sockets open for multiple "
        "connects\n\t-l\t\tListen mode, for inbound connects\n\t-M ttl\t\tOutgoing TTL / Hop Limit\n\t-m "
        "minttl\tMinimum incoming TTL / Hop Limit\n\t-N\t\tShutdown the network socket after EOF on "
        "stdin\n\t-n\t\tSuppress name/port resolutions\n\t-O length\tTCP send buffer length\n\t-o staplefile\tStaple "
        "file\n\t-P proxyuser\tUsername for proxy authentication\n\t-p port\t\tSpecify local port for remote "
        "connects\n\t-R CAfile\tCA bundle\n\t-r\t\tRandomize remote ports\n\t-S\t\tEnable the TCP MD5 signature "
        "option\n\t-s sourceaddr\tLocal source address\n\t-T keyword\tTOS value or TLS options\n\t-U\t\tUse UNIX "
        "domain socket\n\t-u\t\tUDP mode\n\t-V rtable\tSpecify alternate routing table\n\t-v\t\tVerbose\n\t-W "
        "recvlimit\tTerminate after receiving a number of packets\n\t-w timeout\tTimeout for connects and final net "
        "reads\n\t-X proto\tProxy protocol: \"5\" (SOCKS) or \"connect\"\n\t-x addr[:port]\tSpecify "
        "proxy address and port\n\t-Z\t\tPeer certificate file\n\t-z\t\tZero-I/O mode [used for scanning]\n\tPort "
        "numbers can be individual or ranges: lo-hi [inclusive]\n");
    exit(1);
}

void usage(int ret) {
    fprintf(stderr,
            "usage: nc [-46cDdFhklNnrSUuvz] [-C certfile] [-e name] "
            "[-H hash] [-I length]\n"
            "\t  [-i interval] [-K keyfile] [-M ttl] [-m minttl] [-O length]\n"
            "\t  [-o staplefile] [-P proxy_username] [-p source_port] "
            "[-R CAfile]\n"
            "\t  [-s sourceaddr] [-T keyword] [-V rtable] [-W recvlimit] "
            "[-w timeout]\n"
            "\t  [-X proxy_protocol] [-x proxy_address[:port]] "
            "[-Z peercertfile]\n"
            "\t  [destination] [port]\n");
    if (ret)
        exit(1);
}
