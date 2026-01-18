#include "netcat.h"
#include <stddef.h>
#include "syscalls.h"

#ifdef __linux__
#include <linux/vm_sockets.h>
#endif

#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif

#ifndef VMADDR_CID_ANY
#define VMADDR_CID_ANY -1U
#endif

#ifndef VMADDR_CID_LOCAL
#define VMADDR_CID_LOCAL 1
#endif

#ifndef VMADDR_PORT_ANY
#define VMADDR_PORT_ANY -1U
#endif

#ifndef __linux__
#ifndef HAVE_SOCKADDR_VM
struct sockaddr_vm {
    unsigned short svm_family;
    unsigned short svm_reserved1;
    unsigned int svm_port;
    unsigned int svm_cid;
    unsigned char svm_zero[sizeof(struct sockaddr) - sizeof(unsigned short) - sizeof(unsigned short) -
                           sizeof(unsigned int) - sizeof(unsigned int)];
};
#endif
#endif

int vsock_listen(const char* cid_str, const char* port_str) {
    struct sockaddr_vm svm;
    int s;
    const char* errstr;

    memset(&svm, 0, sizeof(svm));
    svm.svm_family = AF_VSOCK;

    if (cid_str == NULL || strcmp(cid_str, "any") == 0)
        svm.svm_cid = VMADDR_CID_ANY;
    else
        svm.svm_cid = (unsigned int)strtonum(cid_str, 0, UINT_MAX, &errstr);

    if (port_str == NULL)
        svm.svm_port = VMADDR_PORT_ANY;
    else
        svm.svm_port = (unsigned int)strtonum(port_str, 0, UINT_MAX, &errstr);

    if ((s = direct_socket(AF_VSOCK, SOCK_STREAM, 0)) == -1)
        return -1;

    set_common_sockopts(s, AF_VSOCK);

    if (direct_bind(s, (struct sockaddr*)&svm, sizeof(svm)) == -1) {
        close(s);
        return -1;
    }

    if (direct_listen(s, 5) == -1) {
        close(s);
        return -1;
    }

    if (vflag) {
        char buf[64];
        snprintf(buf, sizeof(buf), "vsock:%u:%u", svm.svm_cid, svm.svm_port);
        report_sock("Listening", NULL, 0, buf);
    }

    return s;
}

int vsock_connect(const char* cid_str, const char* port_str) {
    struct sockaddr_vm svm;
    int s;
    const char* errstr;

    memset(&svm, 0, sizeof(svm));
    svm.svm_family = AF_VSOCK;

    if (strcmp(cid_str, "local") == 0)
        svm.svm_cid = VMADDR_CID_LOCAL;
    else
        svm.svm_cid = (unsigned int)strtonum(cid_str, 0, UINT_MAX, &errstr);

    svm.svm_port = (unsigned int)strtonum(port_str, 0, UINT_MAX, &errstr);

    if ((s = direct_socket(AF_VSOCK, SOCK_STREAM, 0)) == -1)
        return -1;

    set_common_sockopts(s, AF_VSOCK);

    if (direct_connect(s, (struct sockaddr*)&svm, sizeof(svm)) == -1) {
        close(s);
        return -1;
    }

    return s;
}

/*
 * unix_bind()
 * Returns a unix socket bound to the given path
 */
int unix_bind(char* path, int flags) {
    struct sockaddr_un s_un;
    int s, save_errno;
    socklen_t len;

    /* Create unix domain socket. */
    if ((s = direct_socket(AF_UNIX, flags | (uflag ? SOCK_DGRAM : SOCK_STREAM), 0)) == -1)
        return -1;

    memset(&s_un, 0, sizeof(struct sockaddr_un));
    s_un.sun_family = AF_UNIX;

    if (path[0] == '@') {
        s_un.sun_path[0] = '\0';
        if (strlcpy(&s_un.sun_path[1], &path[1], sizeof(s_un.sun_path) - 1) >= sizeof(s_un.sun_path) - 1) {
            close(s);
            errno = ENAMETOOLONG;
            return -1;
        }
        len = offsetof(struct sockaddr_un, sun_path) + strlen(path);
    }
    else {
        if (strlcpy(s_un.sun_path, path, sizeof(s_un.sun_path)) >= sizeof(s_un.sun_path)) {
            close(s);
            errno = ENAMETOOLONG;
            return -1;
        }
        len = sizeof(s_un);
    }

    if (direct_bind(s, (struct sockaddr*)&s_un, len) == -1) {
        save_errno = errno;
        close(s);
        errno = save_errno;
        return -1;
    }
    if (vflag)
        report_sock("Bound", NULL, 0, path);

    return s;
}

/*
 * unix_connect()
 * Returns a socket connected to a local unix socket. Returns -1 on failure.
 */
int unix_connect(char* path) {
    struct sockaddr_un s_un;
    int s, save_errno;
    socklen_t len;

    if (uflag) {
        if ((s = unix_bind(unix_dg_tmp_socket, SOCK_CLOEXEC)) == -1)
            return -1;
    }
    else {
        if ((s = direct_socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) == -1)
            return -1;
    }

    memset(&s_un, 0, sizeof(struct sockaddr_un));
    s_un.sun_family = AF_UNIX;

    if (path[0] == '@') {
        s_un.sun_path[0] = '\0';
        if (strlcpy(&s_un.sun_path[1], &path[1], sizeof(s_un.sun_path) - 1) >= sizeof(s_un.sun_path) - 1) {
            close(s);
            errno = ENAMETOOLONG;
            return -1;
        }
        len = offsetof(struct sockaddr_un, sun_path) + strlen(path);
    }
    else {
        if (strlcpy(s_un.sun_path, path, sizeof(s_un.sun_path)) >= sizeof(s_un.sun_path)) {
            close(s);
            errno = ENAMETOOLONG;
            return -1;
        }
        len = sizeof(s_un);
    }

    if (direct_connect(s, (struct sockaddr*)&s_un, len) == -1) {
        save_errno = errno;
        close(s);
        errno = save_errno;
        return -1;
    }
    return s;
}

/*
 * unix_listen()
 * Create a unix domain socket, and listen on it.
 */
int unix_listen(char* path) {
    int s;

    if ((s = unix_bind(path, 0)) == -1)
        return -1;
    if (direct_listen(s, 5) == -1) {
        close(s);
        return -1;
    }
    if (vflag)
        report_sock("Listening", NULL, 0, path);

    return s;
}

/*
 * remote_connect()
 * Returns a socket connected to a remote host. Properly binds to a local
 * port or source address if needed. Returns -1 on failure.
 */
int remote_connect(const char* host, const char* port, struct addrinfo hints, char* ipaddr) {
    struct addrinfo *res, *res0;
    int s = -1, error, herr, on = 1, save_errno;

    if ((error = getaddrinfo(host, port, &hints, &res0)))
        errx(1, "getaddrinfo for host \"%s\" port %s: %s", host, port, gai_strerror(error));

    for (res = res0; res; res = res->ai_next) {
        int proto = res->ai_protocol;
#ifdef IPPROTO_MPTCP
        if (mptcpflag && res->ai_protocol == IPPROTO_TCP)
            proto = IPPROTO_MPTCP;
#endif
        if ((s = direct_socket(res->ai_family, res->ai_socktype | SOCK_NONBLOCK, proto)) == -1)
            continue;

        /* Bind to a local port or source address if specified. */
        if (sflag || pflag) {
            struct addrinfo ahints, *ares;

            /* try SO_BINDANY, but don't insist */
            setsockopt(s, SOL_SOCKET, SO_BINDANY, &on, sizeof(on));
            memset(&ahints, 0, sizeof(struct addrinfo));
            ahints.ai_family = res->ai_family;
            ahints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
            ahints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
            ahints.ai_flags = AI_PASSIVE;
            if ((error = getaddrinfo(sflag, pflag, &ahints, &ares)))
                errx(1, "getaddrinfo: %s", gai_strerror(error));

            if (direct_bind(s, (struct sockaddr*)ares->ai_addr, ares->ai_addrlen) == -1)
                err(1, "bind failed");
            freeaddrinfo(ares);
        }

        set_common_sockopts(s, res->ai_family);

        if (ipaddr != NULL) {
            herr = getnameinfo(res->ai_addr, res->ai_addrlen, ipaddr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            switch (herr) {
                case 0:
                    break;
                case EAI_SYSTEM:
                    err(1, "getnameinfo");
                default:
                    errx(1, "getnameinfo: %s", gai_strerror(herr));
            }
        }

        if (timeout_connect(s, res->ai_addr, res->ai_addrlen) == 0)
            break;

        if (vflag) {
            /* only print IP if there is something to report */
            if (nflag || ipaddr == NULL || (strncmp(host, ipaddr, NI_MAXHOST) == 0))
                warn("connect to %s port %s (%s) failed", host, port, uflag ? "udp" : "tcp");
            else
                warn("connect to %s (%s) port %s (%s) failed", host, ipaddr, port, uflag ? "udp" : "tcp");
        }

        save_errno = errno;
        close(s);
        errno = save_errno;
        s = -1;
    }

    freeaddrinfo(res0);

    return s;
}

int timeout_connect(int s, const struct sockaddr* name, socklen_t namelen) {
    struct pollfd pfd;
    socklen_t optlen;
    int optval;
    int ret;

    if ((ret = direct_connect(s, name, namelen)) != 0 && errno == EINPROGRESS) {
        pfd.fd = s;
        pfd.events = POLLOUT;
        if ((ret = poll(&pfd, 1, timeout)) == 1) {
            optlen = sizeof(optval);
            if ((ret = getsockopt(s, SOL_SOCKET, SO_ERROR, &optval, &optlen)) == 0) {
                errno = optval;
                ret = optval == 0 ? 0 : -1;
            }
        }
        else if (ret == 0) {
            errno = ETIMEDOUT;
            ret = -1;
        }
        else
            err(1, "poll failed");
    }

    return ret;
}

/*
 * local_listen()
 * Returns a socket listening on a local port, binds to specified source
 * address. Returns -1 on failure.
 */
int local_listen(const char* host, const char* port, struct addrinfo hints) {
    struct addrinfo *res, *res0;
    int s = -1, ret, x = 1, save_errno;
    int error;

    /* Allow nodename to be null. */
    hints.ai_flags |= AI_PASSIVE;

    /*
     * In the case of binding to a wildcard address
     * default to binding to an ipv4 address.
     */
    if (host == NULL && hints.ai_family == AF_UNSPEC)
        hints.ai_family = AF_INET;

    if ((error = getaddrinfo(host, port, &hints, &res0)))
        errx(1, "getaddrinfo: %s", gai_strerror(error));

    for (res = res0; res; res = res->ai_next) {
        int proto = res->ai_protocol;
#ifdef IPPROTO_MPTCP
        if (mptcpflag && res->ai_protocol == IPPROTO_TCP)
            proto = IPPROTO_MPTCP;
#endif
        if ((s = direct_socket(res->ai_family, res->ai_socktype, proto)) == -1)
            continue;

        ret = setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &x, sizeof(x));
        if (ret == -1)
            err(1, NULL);

        set_common_sockopts(s, res->ai_family);

        if (direct_bind(s, (struct sockaddr*)res->ai_addr, res->ai_addrlen) == 0)
            break;

        save_errno = errno;
        close(s);
        errno = save_errno;
        s = -1;
    }

    if (!uflag && s != -1) {
        if (direct_listen(s, 1) == -1)
            err(1, "listen");
    }
    if (vflag && s != -1) {
        struct sockaddr_storage ss;
        socklen_t len;

        len = sizeof(ss);
        if (getsockname(s, (struct sockaddr*)&ss, &len) == -1)
            err(1, "getsockname");
        report_sock(uflag ? "Bound" : "Listening", (struct sockaddr*)&ss, len, NULL);
    }

    freeaddrinfo(res0);

    return s;
}

/*
 * udptest()
 * Do a few writes to see if the UDP port is there.
 * Fails once PF state table is full.
 */
int udptest(int s) {
    int i, ret;

    /* Only write to the socket in scan mode or interactive mode. */
    if (!zflag && !isatty(STDIN_FILENO))
        return 0;

    for (i = 0; i <= 3; i++) {
        if (direct_write(s, "X", 1) == 1)
            ret = 1;
        else
            ret = -1;
    }
    return ret;
}

void connection_info(const char* host, const char* port, const char* proto, const char* ipaddr) {
    struct servent* sv;
    char* service = "*";

    /* Look up service name unless -n. */
    if (!nflag) {
        const char* errstr;

        int p = strtonum(port, 1, PORT_MAX, &errstr);
        if (errstr)
            errx(1, "port number %s: %s", errstr, port);
        sv = getservbyport(htons(p), proto);
        if (sv != NULL)
            service = sv->s_name;
    }

    if (jflag) {
        char tbuf[32];
        time_t now;
        struct tm* tm_info;

        time(&now);
        tm_info = gmtime(&now);
        strftime(tbuf, sizeof(tbuf), "%Y-%m-%dT%H:%M:%SZ", tm_info);

        fprintf(stderr,
                "{\"timestamp\":\"%s\",\"level\":\"info\",\"event\":\"connection_succeeded\",\"host\":\"%s\",\"ip\":\"%"
                "s\",\"port\":\"%s\",\"proto\":\"%s\",\"service\":\"%s\"}\n",
                tbuf, host, ipaddr, port, proto, service);
    }
    else {
        fprintf(stderr, "Connection to %s", host);

        /*
         * if we aren't connecting thru a proxy and
         * there is something to report, print IP
         */
        if (!nflag && !xflag && strcmp(host, ipaddr) != 0)
            fprintf(stderr, " (%s)", ipaddr);

        fprintf(stderr, " %s port [%s/%s] succeeded!\n", port, proto, service);
    }
}

void set_common_sockopts(int s, int af) {
    int x = 1;

    if (Dflag) {
        if (setsockopt(s, SOL_SOCKET, SO_DEBUG, &x, sizeof(x)) == -1)
            err(1, NULL);
    }
    if (Tflag != -1) {
        if (af == AF_INET && setsockopt(s, IPPROTO_IP, IP_TOS, &Tflag, sizeof(Tflag)) == -1)
            err(1, "set IP ToS");

        else if (af == AF_INET6 && setsockopt(s, IPPROTO_IPV6, IPV6_TCLASS, &Tflag, sizeof(Tflag)) == -1)
            err(1, "set IPv6 traffic class");
    }
    if (Iflag) {
        if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &Iflag, sizeof(Iflag)) == -1)
            err(1, "set TCP receive buffer size");
    }
    if (Oflag) {
        if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &Oflag, sizeof(Oflag)) == -1)
            err(1, "set TCP send buffer size");
    }

    if (ttl != -1) {
        if (af == AF_INET && setsockopt(s, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)))
            err(1, "set IP TTL");

        else if (af == AF_INET6 && setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl)))
            err(1, "set IPv6 unicast hops");
    }

    if (minttl != -1) {
        if (af == AF_INET && setsockopt(s, IPPROTO_IP, IP_MINTTL, &minttl, sizeof(minttl)))
            err(1, "set IP min TTL");

        else if (af == AF_INET6 && setsockopt(s, IPPROTO_IPV6, IPV6_MINHOPCOUNT, &minttl, sizeof(minttl)))
            err(1, "set IPv6 min hop count");
    }

#ifdef SO_MARK
    if (sockmark != -1) {
        if (setsockopt(s, SOL_SOCKET, SO_MARK, &sockmark, sizeof(sockmark)) == -1)
            err(1, "set SO_MARK");
    }
#endif

#ifdef SO_PRIORITY
    if (sockpriority != -1) {
        if (setsockopt(s, SOL_SOCKET, SO_PRIORITY, &sockpriority, sizeof(sockpriority)) == -1)
            err(1, "set SO_PRIORITY");
    }
#endif

#ifdef SO_BINDTODEVICE
    if (iface != NULL) {
        if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface)) == -1)
            err(1, "set SO_BINDTODEVICE");
    }
#endif

    if (transparent) {
#ifdef IP_TRANSPARENT
        if (af == AF_INET || af == AF_INET6) {
            if (setsockopt(s, SOL_IP, IP_TRANSPARENT, &x, sizeof(x)) == -1)
                err(1, "set IP_TRANSPARENT");
        }
#endif
    }

    if (tfoflag) {
#ifdef TCP_FASTOPEN_CONNECT
        if (!lflag) {
            if (setsockopt(s, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &x, sizeof(x)) == -1)
                err(1, "set TCP_FASTOPEN_CONNECT");
        }
#endif
#ifdef TCP_FASTOPEN
        if (lflag) {
            int qlen = 5;
            if (setsockopt(s, IPPROTO_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen)) == -1)
                err(1, "set TCP_FASTOPEN");
        }
#endif
    }
}

int process_tos_opt(char* s, int* val) {
    /* DiffServ Codepoints and other TOS mappings */
    const struct toskeywords {
        const char* keyword;
        int val;
    } *t, toskeywords[] = {
              {"af11", IPTOS_DSCP_AF11},
              {"af12", IPTOS_DSCP_AF12},
              {"af13", IPTOS_DSCP_AF13},
              {"af21", IPTOS_DSCP_AF21},
              {"af22", IPTOS_DSCP_AF22},
              {"af23", IPTOS_DSCP_AF23},
              {"af31", IPTOS_DSCP_AF31},
              {"af32", IPTOS_DSCP_AF32},
              {"af33", IPTOS_DSCP_AF33},
              {"af41", IPTOS_DSCP_AF41},
              {"af42", IPTOS_DSCP_AF42},
              {"af43", IPTOS_DSCP_AF43},
              {"critical", IPTOS_PREC_CRITIC_ECP},
              {"cs0", IPTOS_DSCP_CS0},
              {"cs1", IPTOS_DSCP_CS1},
              {"cs2", IPTOS_DSCP_CS2},
              {"cs3", IPTOS_DSCP_CS3},
              {"cs4", IPTOS_DSCP_CS4},
              {"cs5", IPTOS_DSCP_CS5},
              {"cs6", IPTOS_DSCP_CS6},
              {"cs7", IPTOS_DSCP_CS7},
              {"ef", IPTOS_DSCP_EF},
              {"inetcontrol", IPTOS_PREC_INTERNETCONTROL},
              {"lowdelay", IPTOS_LOWDELAY},
              {"netcontrol", IPTOS_PREC_NETCONTROL},
              {"reliability", IPTOS_RELIABILITY},
              {"throughput", IPTOS_THROUGHPUT},
              {"va", IPTOS_DSCP_VA},
              {NULL, -1},
          };

    for (t = toskeywords; t->keyword != NULL; t++) {
        if (strcmp(s, t->keyword) == 0) {
            *val = t->val;
            return 1;
        }
    }

    return 0;
}
