/* $OpenBSD: netcat.c,v 1.237 2025/12/06 09:48:30 phessler Exp $ */
/*
 * Copyright (c) 2001 Eric Jackson <ericj@monkey.org>
 * Copyright (c) 2015 Bob Beck.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Re-written nc(1) for OpenBSD. Original implementation by
 * *Hobbit* <hobbit@avian.org>.
 */

#include "netcat.h"

/* Command Line Options */
int dflag;          /* detached, no stdin */
int Fflag;          /* fdpass sock to stdout */
unsigned int iflag; /* Interval Flag */
int kflag;          /* More than one connect */
int lflag;          /* Bind to local port */
int Nflag;          /* shutdown() network socket */
int nflag;          /* Don't do name look up */
char* Pflag;        /* Proxy username */
char* pflag;        /* Localport flag */
int rflag;          /* Random ports flag */
char* sflag;        /* Source Address */
int uflag;          /* UDP - Default to TCP */
int vflag;          /* Verbosity */
int xflag;          /* Socks proxy */
int zflag;          /* Port Scan Flag */
int Dflag;          /* sodebug */
int Iflag;          /* TCP receive buffer size */
int Oflag;          /* TCP send buffer size */
int Sflag;          /* TCP MD5 signature option */
int Tflag = -1;     /* IP Type of Service */
int rtableid = -1;

int usetls;           /* use TLS */
const char* Cflag;    /* Public cert file */
const char* Kflag;    /* Private key file */
const char* oflag;    /* OCSP stapling file */
const char* Rflag;    /* Root CA file */
int tls_cachanged;    /* Using non-default CA file */
int TLSopt;           /* TLS options */
char* tls_expectname; /* required name in peer cert */
char* tls_expecthash; /* required hash of peer cert */
char* tls_ciphers;    /* TLS ciphers */
char* tls_protocols;  /* TLS protocols */
char* tls_alpn;       /* TLS ALPN */
FILE* Zflag;          /* file to save peer cert */

int recvcount, recvlimit;
int timeout = -1;
int family = AF_UNSPEC;
char* portlist[PORT_MAX + 1];
char* unix_dg_tmp_socket;
int ttl = -1;
int minttl = -1;

int main(int argc, char* argv[]) {
    int ch, s = -1, ret, socksv;
    char *host, *uport;
    char ipaddr[NI_MAXHOST];
    struct addrinfo hints;
    socklen_t len;
    struct sockaddr_storage cliaddr;
    char *proxy = NULL, *proxyport = NULL;
    const char* errstr;
    struct addrinfo proxyhints;
    char unix_dg_tmp_socket_buf[UNIX_DG_TMP_SOCKET_SIZE];
    struct tls_config* tls_cfg = NULL;
    struct tls* tls_ctx = NULL;
    uint32_t protocols;

    ret = 1;
    socksv = 5;
    host = NULL;
    uport = NULL;
    Rflag = tls_default_ca_cert_file();

    signal(SIGPIPE, SIG_IGN);

    while ((ch = getopt(argc, argv, "46C:cDde:FH:hI:i:K:klM:m:NnO:o:P:p:R:rSs:T:UuV:vW:w:X:x:Z:z")) != -1) {
        switch (ch) {
            case '4':
                family = AF_INET;
                break;
            case '6':
                family = AF_INET6;
                break;
            case 'U':
                family = AF_UNIX;
                break;
            case 'X':
                if (strcasecmp(optarg, "connect") == 0)
                    socksv = -1; /* HTTP proxy CONNECT */
                else if (strcmp(optarg, "4") == 0) {
                    warnx(
                        "Warning: SOCKSv4 proxy support is deprecated and will be removed in a future version. Please "
                        "use SOCKSv5.");
                    socksv = 4; /* SOCKS v.4 */
                }
                else if (strcasecmp(optarg, "4A") == 0) {
                    warnx(
                        "Warning: SOCKSv4A proxy support is deprecated and will be removed in a future version. Please "
                        "use SOCKSv5.");
                    socksv = 44; /* SOCKS v.4A */
                }
                else if (strcmp(optarg, "5") == 0)
                    socksv = 5; /* SOCKS v.5 */
                else
                    errx(1, "unsupported proxy protocol");
                break;
            case 'C':
                Cflag = optarg;
                break;
            case 'c':
                usetls = 1;
                break;
            case 'd':
                dflag = 1;
                break;
            case 'e':
                tls_expectname = optarg;
                break;
            case 'F':
                Fflag = 1;
                break;
            case 'H':
                tls_expecthash = optarg;
                break;
            case 'h':
                help();
                break;
            case 'i':
                iflag = strtonum(optarg, 0, UINT_MAX, &errstr);
                if (errstr)
                    errx(1, "interval %s: %s", errstr, optarg);
                break;
            case 'K':
                Kflag = optarg;
                break;
            case 'k':
                kflag = 1;
                break;
            case 'l':
                lflag = 1;
                break;
            case 'M':
                ttl = strtonum(optarg, 0, 255, &errstr);
                if (errstr)
                    errx(1, "ttl is %s", errstr);
                break;
            case 'm':
                minttl = strtonum(optarg, 0, 255, &errstr);
                if (errstr)
                    errx(1, "minttl is %s", errstr);
                break;
            case 'N':
                Nflag = 1;
                break;
            case 'n':
                nflag = 1;
                break;
            case 'P':
                Pflag = optarg;
                break;
            case 'p':
                pflag = optarg;
                break;
            case 'R':
                tls_cachanged = 1;
                Rflag = optarg;
                break;
            case 'r':
                rflag = 1;
                break;
            case 's':
                sflag = optarg;
                break;
            case 'u':
                uflag = 1;
                break;
            case 'V':
                rtableid = (int)strtonum(optarg, 0, RT_TABLEID_MAX, &errstr);
                if (errstr)
                    errx(1, "rtable %s: %s", errstr, optarg);
                break;
            case 'v':
                vflag = 1;
                break;
            case 'W':
                recvlimit = strtonum(optarg, 1, INT_MAX, &errstr);
                if (errstr)
                    errx(1, "receive limit %s: %s", errstr, optarg);
                break;
            case 'w':
                timeout = strtonum(optarg, 0, INT_MAX / 1000, &errstr);
                if (errstr)
                    errx(1, "timeout %s: %s", errstr, optarg);
                timeout *= 1000;
                break;
            case 'x':
                xflag = 1;
                if ((proxy = strdup(optarg)) == NULL)
                    err(1, NULL);
                break;
            case 'Z':
                if (strcmp(optarg, "-") == 0)
                    Zflag = stderr;
                else if ((Zflag = fopen(optarg, "w")) == NULL)
                    err(1, "can't open %s", optarg);
                break;
            case 'z':
                zflag = 1;
                break;
            case 'D':
                Dflag = 1;
                break;
            case 'I':
                Iflag = strtonum(optarg, 1, 65536 << 14, &errstr);
                if (errstr != NULL)
                    errx(1, "TCP receive window %s: %s", errstr, optarg);
                break;
            case 'O':
                Oflag = strtonum(optarg, 1, 65536 << 14, &errstr);
                if (errstr != NULL)
                    errx(1, "TCP send window %s: %s", errstr, optarg);
                break;
            case 'o':
                oflag = optarg;
                break;
            case 'S':
                Sflag = 1;
                break;
            case 'T':
                errstr = NULL;
                errno = 0;
                if (process_tls_opt(optarg, &TLSopt))
                    break;
                if (process_tos_opt(optarg, &Tflag))
                    break;
                if (strlen(optarg) > 1 && optarg[0] == '0' && optarg[1] == 'x')
                    Tflag = (int)strtol(optarg, NULL, 16);
                else
                    Tflag = (int)strtonum(optarg, 0, 255, &errstr);
                if (Tflag < 0 || Tflag > 255 || errstr || errno)
                    errx(1, "illegal tos/tls value %s", optarg);
                break;
            default:
                usage(1);
        }
    }
    argc -= optind;
    argv += optind;

    if (rtableid >= 0)
        if (setrtable(rtableid) == -1)
            err(1, "setrtable");

    /* Cruft to make sure options are clean, and used properly. */
    if (argc == 1 && family == AF_UNIX) {
        host = argv[0];
    }
    else if (argc == 1 && lflag) {
        uport = argv[0];
    }
    else if (argc == 2) {
        host = argv[0];
        uport = argv[1];
    }
    else
        usage(1);

    if (usetls) {
        if (Cflag && unveil(Cflag, "r") == -1)
            err(1, "unveil %s", Cflag);
        if (unveil(Rflag, "r") == -1)
            err(1, "unveil %s", Rflag);
        if (Kflag && unveil(Kflag, "r") == -1)
            err(1, "unveil %s", Kflag);
        if (oflag && unveil(oflag, "r") == -1)
            err(1, "unveil %s", oflag);
    }
    else if (family == AF_UNIX && uflag && lflag && !kflag) {
        /*
         * After recvfrom(2) from client, the server connects
         * to the client socket.  As the client path is determined
         * during runtime, we cannot unveil(2).
         */
    }
    else {
        if (family == AF_UNIX) {
            if (unveil(host, "rwc") == -1)
                err(1, "unveil %s", host);
            if (uflag && !kflag) {
                if (sflag) {
                    if (unveil(sflag, "rwc") == -1)
                        err(1, "unveil %s", sflag);
                }
                else {
                    if (unveil("/tmp", "rwc") == -1)
                        err(1, "unveil /tmp");
                }
            }
        }
        else {
            /* no filesystem visibility */
            if (unveil("/", "") == -1)
                err(1, "unveil /");
        }
    }

    if (family == AF_UNIX) {
        if (pledge("stdio rpath wpath cpath tmppath unix", NULL) == -1)
            err(1, "pledge");
    }
    else if (Fflag && Pflag) {
        if (pledge("stdio inet dns sendfd tty", NULL) == -1)
            err(1, "pledge");
    }
    else if (Fflag) {
        if (pledge("stdio inet dns sendfd", NULL) == -1)
            err(1, "pledge");
    }
    else if (Pflag && usetls) {
        if (pledge("stdio rpath inet dns tty", NULL) == -1)
            err(1, "pledge");
    }
    else if (Pflag) {
        if (pledge("stdio inet dns tty", NULL) == -1)
            err(1, "pledge");
    }
    else if (usetls) {
        if (pledge("stdio rpath inet dns", NULL) == -1)
            err(1, "pledge");
    }
    else if (pledge("stdio inet dns", NULL) == -1)
        err(1, "pledge");

    if (lflag && sflag)
        errx(1, "cannot use -s and -l");
    if (lflag && pflag)
        errx(1, "cannot use -p and -l");
    if (lflag && zflag)
        errx(1, "cannot use -z and -l");
    if (!lflag && kflag)
        errx(1, "must use -l with -k");
    if (uflag && usetls)
        errx(1, "cannot use -c and -u");
    if ((family == AF_UNIX) && usetls)
        errx(1, "cannot use -c and -U");
    if ((family == AF_UNIX) && Fflag)
        errx(1, "cannot use -F and -U");
    if (Fflag && usetls)
        errx(1, "cannot use -c and -F");
    if (TLSopt && !usetls)
        errx(1, "you must specify -c to use TLS options");
    if (Cflag && !usetls)
        errx(1, "you must specify -c to use -C");
    if (Kflag && !usetls)
        errx(1, "you must specify -c to use -K");
    if (Zflag && !usetls)
        errx(1, "you must specify -c to use -Z");
    if (oflag && !Cflag)
        errx(1, "you must specify -C to use -o");
    if (tls_cachanged && !usetls)
        errx(1, "you must specify -c to use -R");
    if (tls_expecthash && !usetls)
        errx(1, "you must specify -c to use -H");
    if (tls_expectname && !usetls)
        errx(1, "you must specify -c to use -e");

    /* Get name of temporary socket for unix datagram client */
    if ((family == AF_UNIX) && uflag && !lflag) {
        if (sflag) {
            unix_dg_tmp_socket = sflag;
        }
        else {
            strlcpy(unix_dg_tmp_socket_buf, "/tmp/nc.XXXXXXXXXX", UNIX_DG_TMP_SOCKET_SIZE);
            if (mktemp(unix_dg_tmp_socket_buf) == NULL)
                err(1, "mktemp");
            unix_dg_tmp_socket = unix_dg_tmp_socket_buf;
        }
    }

    /* Initialize addrinfo structure. */
    if (family != AF_UNIX) {
        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = family;
        hints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
        hints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
        if (nflag)
            hints.ai_flags |= AI_NUMERICHOST;
    }

    if (xflag) {
        if (uflag)
            errx(1, "no proxy support for UDP mode");

        if (lflag)
            errx(1, "no proxy support for listen");

        if (family == AF_UNIX)
            errx(1, "no proxy support for unix sockets");

        if (sflag)
            errx(1, "no proxy support for local source address");

        if (*proxy == '[') {
            ++proxy;
            proxyport = strchr(proxy, ']');
            if (proxyport == NULL)
                errx(1, "missing closing bracket in proxy");
            *proxyport++ = '\0';
            if (*proxyport == '\0')
                /* Use default proxy port. */
                proxyport = NULL;
            else {
                if (*proxyport == ':')
                    ++proxyport;
                else
                    errx(1, "garbage proxy port delimiter");
            }
        }
        else {
            proxyport = strrchr(proxy, ':');
            if (proxyport != NULL)
                *proxyport++ = '\0';
        }

        memset(&proxyhints, 0, sizeof(struct addrinfo));
        proxyhints.ai_family = family;
        proxyhints.ai_socktype = SOCK_STREAM;
        proxyhints.ai_protocol = IPPROTO_TCP;
        if (nflag)
            proxyhints.ai_flags |= AI_NUMERICHOST;
    }

    if (usetls) {
        if ((tls_cfg = tls_config_new()) == NULL)
            errx(1, "unable to allocate TLS config");
        if (Rflag && tls_config_set_ca_file(tls_cfg, Rflag) == -1)
            errx(1, "%s", tls_config_error(tls_cfg));
        if (Cflag && tls_config_set_cert_file(tls_cfg, Cflag) == -1)
            errx(1, "%s", tls_config_error(tls_cfg));
        if (Kflag && tls_config_set_key_file(tls_cfg, Kflag) == -1)
            errx(1, "%s", tls_config_error(tls_cfg));
        if (oflag && tls_config_set_ocsp_staple_file(tls_cfg, oflag) == -1)
            errx(1, "%s", tls_config_error(tls_cfg));
        if (tls_config_parse_protocols(&protocols, tls_protocols) == -1)
            errx(1, "invalid TLS protocols `%s'", tls_protocols);
        if (tls_config_set_protocols(tls_cfg, protocols) == -1)
            errx(1, "%s", tls_config_error(tls_cfg));
        if (tls_config_set_ciphers(tls_cfg, tls_ciphers) == -1)
            errx(1, "%s", tls_config_error(tls_cfg));
        if (tls_alpn != NULL && tls_config_set_alpn(tls_cfg, tls_alpn) == -1)
            errx(1, "%s", tls_config_error(tls_cfg));
        if (!lflag && (TLSopt & TLS_CCERT))
            errx(1, "clientcert is only valid with -l");
        if (TLSopt & TLS_NONAME)
            tls_config_insecure_noverifyname(tls_cfg);
        if (TLSopt & TLS_NOVERIFY) {
            if (tls_expecthash != NULL)
                errx(1,
                     "-H and -T noverify may not be used "
                     "together");
            tls_config_insecure_noverifycert(tls_cfg);
        }
        if (TLSopt & TLS_MUSTSTAPLE)
            tls_config_ocsp_require_stapling(tls_cfg);

        if (Pflag) {
            if (pledge("stdio inet dns tty", NULL) == -1)
                err(1, "pledge");
        }
        else if (pledge("stdio inet dns", NULL) == -1)
            err(1, "pledge");
    }
    if (lflag) {
        ret = 0;

        if (family == AF_UNIX) {
            if (uflag)
                s = unix_bind(host, 0);
            else
                s = unix_listen(host);
        }

        if (usetls) {
            tls_config_verify_client_optional(tls_cfg);
            if ((tls_ctx = tls_server()) == NULL)
                errx(1, "tls server creation failed");
            if (tls_configure(tls_ctx, tls_cfg) == -1)
                errx(1, "tls configuration failed (%s)", tls_error(tls_ctx));
        }
        /* Allow only one connection at a time, but stay alive. */
        for (;;) {
            if (family != AF_UNIX) {
                if (s != -1)
                    close(s);
                s = local_listen(host, uport, hints);
            }
            if (s == -1)
                err(1, NULL);
            if (uflag && kflag) {
                if (family == AF_UNIX) {
                    if (pledge("stdio unix", NULL) == -1)
                        err(1, "pledge");
                }
                /*
                 * For UDP and -k, don't connect the socket,
                 * let it receive datagrams from multiple
                 * socket pairs.
                 */
                readwrite(s, NULL);
            }
            else if (uflag && !kflag) {
                /*
                 * For UDP and not -k, we will use recvfrom()
                 * initially to wait for a caller, then use
                 * the regular functions to talk to the caller.
                 */
                int rv;
                char buf[2048];
                struct sockaddr_storage z;

                len = sizeof(z);
                rv = recvfrom(s, buf, sizeof(buf), MSG_PEEK, (struct sockaddr*)&z, &len);
                if (rv == -1)
                    err(1, "recvfrom");

                rv = connect(s, (struct sockaddr*)&z, len);
                if (rv == -1)
                    err(1, "connect");

                if (family == AF_UNIX) {
                    if (pledge("stdio unix", NULL) == -1)
                        err(1, "pledge");
                }
                if (vflag)
                    report_sock("Connection received", (struct sockaddr*)&z, len, family == AF_UNIX ? host : NULL);

                readwrite(s, NULL);
            }
            else {
                struct tls* tls_cctx = NULL;
                int connfd;

                len = sizeof(cliaddr);
                connfd = accept4(s, (struct sockaddr*)&cliaddr, &len, SOCK_NONBLOCK);
                if (connfd == -1) {
                    /* For now, all errnos are fatal */
                    err(1, "accept");
                }
                if (vflag)
                    report_sock("Connection received", (struct sockaddr*)&cliaddr, len,
                                family == AF_UNIX ? host : NULL);
                if ((usetls) && (tls_cctx = tls_setup_server(tls_ctx, connfd, host)))
                    readwrite(connfd, tls_cctx);
                if (!usetls)
                    readwrite(connfd, NULL);
                if (tls_cctx)
                    timeout_tls(s, tls_cctx, tls_close);
                close(connfd);
                tls_free(tls_cctx);
            }

            if (!kflag)
                break;
        }
    }
    else if (family == AF_UNIX) {
        ret = 0;

        if ((s = unix_connect(host)) > 0) {
            if (!zflag)
                readwrite(s, NULL);
            close(s);
        }
        else {
            warn("%s", host);
            ret = 1;
        }

        if (uflag)
            unlink(unix_dg_tmp_socket);
        return ret;
    }
    else {
        int i = 0;

        /* Construct the portlist[] array. */
        build_ports(uport);

        /* Cycle through portlist, connecting to each port. */
        for (s = -1, i = 0; portlist[i] != NULL; i++) {
            if (s != -1)
                close(s);
            tls_free(tls_ctx);
            tls_ctx = NULL;

            if (usetls) {
                if ((tls_ctx = tls_client()) == NULL)
                    errx(1, "tls client creation failed");
                if (tls_configure(tls_ctx, tls_cfg) == -1)
                    errx(1, "tls configuration failed (%s)", tls_error(tls_ctx));
            }
            if (xflag)
                s = socks_connect(host, portlist[i], hints, proxy, proxyport, proxyhints, socksv, Pflag);
            else
                s = remote_connect(host, portlist[i], hints, ipaddr);

            if (s == -1)
                continue;

            ret = 0;
            if (vflag || zflag) {
                int print_info = 1;

                /* For UDP, make sure we are connected. */
                if (uflag) {
                    /* No info on failed or skipped test. */
                    if ((print_info = udptest(s)) == -1) {
                        ret = 1;
                        continue;
                    }
                }
                if (print_info == 1)
                    connection_info(host, portlist[i], uflag ? "udp" : "tcp", ipaddr);
            }
            if (Fflag)
                fdpass(s);
            else {
                if (usetls)
                    tls_setup_client(tls_ctx, s, host);
                if (!zflag)
                    readwrite(s, tls_ctx);
                if (tls_ctx)
                    timeout_tls(s, tls_ctx, tls_close);
            }
        }
    }

    if (s != -1)
        close(s);
    tls_free(tls_ctx);
    tls_config_free(tls_cfg);

    return ret;
}