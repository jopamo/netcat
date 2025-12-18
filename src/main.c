#include "config.h"
#include "nc_ctx.h"
#include "resolve.h"
#include "connect.h"
#include "io_pump.h"
#include "telnet.h"
#include "hexdump.h"
#include "exec.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>

static struct nc_ctx* g_ctx = NULL;

static void handle_term(int sig) {
    if (g_ctx) {
        g_ctx->got_signal = sig;
        if (g_ctx->netfd >= 0)
            close(g_ctx->netfd);
    }
}

static void setup_signals(struct nc_ctx* ctx) {
    g_ctx = ctx;
    signal(SIGINT, handle_term);
    signal(SIGQUIT, handle_term);
    signal(SIGTERM, handle_term);
#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif
}

static void show_help(struct nc_ctx* ctx) {
    ctx->verbose = true;
    nc_holler(ctx, "Netcat modular implementation v1.10");
    nc_holler(ctx, "Usage: nc [options] hostname port [port] ...");
    nc_holler(ctx, "       nc -l [options] [hostname] [port]");
    nc_holler(ctx, "");
    nc_holler(ctx, "Options:");
    nc_holler(ctx, "  -4               Use IPv4 only");
#ifdef NC_ENABLE_IPV6
    nc_holler(ctx, "  -6               Use IPv6 only");
#endif
    nc_holler(ctx, "  -b               Allow broadcast");
#ifdef GAPING_SECURITY_HOLE
    nc_holler(ctx, "  -c cmd           Execute shell command [DANGEROUS]");
    nc_holler(ctx, "  -e prog          Execute program [DANGEROUS]");
#endif
    nc_holler(ctx, "  -h               This help text");
    nc_holler(ctx, "  -i secs          Delay interval for lines sent");
    nc_holler(ctx, "  -l               Listen mode");
    nc_holler(ctx, "  -n               Numeric-only, no DNS resolution");
    nc_holler(ctx, "  -o file          Hexdump traffic to file");
    nc_holler(ctx, "  -p port          Local source port");
    nc_holler(ctx, "  -q secs          Quit after stdin EOF, delay secs");
    nc_holler(ctx, "  -r               Randomize local and remote ports");
    nc_holler(ctx, "  -s addr          Local source address");
#ifdef TELNET
    nc_holler(ctx, "  -t               Answer TELNET negotiation");
#endif
    nc_holler(ctx, "  -u               UDP mode");
    nc_holler(ctx, "  -v               Verbose (use twice for more)");
    nc_holler(ctx, "  -w secs          Timeout for connects and reads");
    nc_holler(ctx, "  -z               Zero-I/O mode (port scanning)");
    nc_holler(ctx, "");
    nc_holler(ctx, "Ports can be single values or ranges: lo-hi");
    nc_ctx_cleanup(ctx);
    exit(0);
}

static void format_addr(const struct sockaddr_storage* sa, socklen_t slen, bool numeric, char* out, size_t out_sz) {
    if (nc_reverse_name((const struct sockaddr*)sa, slen, out, out_sz, numeric) != 0) {
        strncpy(out, "unknown", out_sz - 1);
        out[out_sz - 1] = '\0';
    }
}

static bool addr_equal(const struct sockaddr_storage* a, const struct sockaddr_storage* b) {
    if (a->ss_family != b->ss_family)
        return false;
    if (a->ss_family == AF_INET) {
        return ((struct sockaddr_in*)a)->sin_addr.s_addr == ((struct sockaddr_in*)b)->sin_addr.s_addr;
    }
#if NC_HAVE_IPV6
    if (a->ss_family == AF_INET6) {
        return memcmp(&((struct sockaddr_in6*)a)->sin6_addr, &((struct sockaddr_in6*)b)->sin6_addr,
                      sizeof(struct in6_addr)) == 0;
    }
#endif
    return false;
}

static int run_listen(struct nc_ctx* ctx, int argc, char** argv, int argi) {
    const char* filter_host = NULL;
    const char* filter_port_str = NULL;
    if (argi < argc) {
        filter_host = argv[argi++];
    }
    if (argi < argc) {
        filter_port_str = argv[argi++];
    }
    if (argi < argc) {
        nc_bail(ctx, "Too many arguments for listen mode");
    }

    if (filter_port_str) {
        unsigned short fp = nc_resolve_port(ctx, filter_port_str);
        if (fp == 0)
            nc_bail(ctx, "invalid port %s", filter_port_str);
        ctx->expected_port = fp;
    }

    if (filter_host) {
        char service[16] = {0};
        if (ctx->expected_port)
            snprintf(service, sizeof(service), "%u", ctx->expected_port);
        if (nc_resolve_one(filter_host, service[0] ? service : NULL, ctx->addr_family, ctx->proto, &ctx->expected_peer,
                           &ctx->expected_peer_len, ctx->numeric_only) < 0) {
            nc_bail(ctx, "Can't resolve %s", filter_host);
        }
        ctx->expect_peer = true;
    }

    if (ctx->proto == NC_UDP && ctx->ourport == 0) {
        nc_bail(ctx, "UDP listen needs -p");
    }

    int lfd = nc_listen(ctx);
    if (lfd < 0)
        return 1;

    if (ctx->verbose) {
        char local[NI_MAXHOST];
        format_addr(&ctx->local_addr, ctx->local_addrlen, true, local, sizeof(local));
        nc_holler(ctx, "listening on %s %u ...", local, ctx->ourport);
    }

    int fd = nc_accept(ctx, lfd);
    if (fd < 0)
        nc_bail(ctx, "no connection");

    if (ctx->expect_peer) {
        if (!addr_equal(&ctx->expected_peer, &ctx->remote_addr))
            nc_bail(ctx, "invalid connection source");
        if (ctx->expected_port && ctx->expected_port != nc_get_port(&ctx->remote_addr))
            nc_bail(ctx, "invalid connection source port");
    }

    char remote[NI_MAXHOST];
    format_addr(&ctx->remote_addr, ctx->remote_addrlen, ctx->numeric_only, remote, sizeof(remote));
    if (ctx->verbose) {
        nc_holler(ctx, "connect from %s %u", remote, nc_get_port(&ctx->remote_addr));
    }

#ifdef GAPING_SECURITY_HOLE
    if (ctx->exec_prog) {
        nc_exec_after_connect(ctx, fd);
    }
#endif

    if (ctx->zero_io) {
        close(fd);
        return 0;
    }

    struct io_buf to_net = {0}, to_out = {0};
    return nc_pump_io(ctx, fd, &to_net, &to_out);
}

static int run_connect(struct nc_ctx* ctx, int argc, char** argv, int argi) {
    if (argi >= argc)
        nc_bail(ctx, "no destination");

    strncpy(ctx->remote_host, argv[argi], sizeof(ctx->remote_host) - 1);
    ctx->remote_host[sizeof(ctx->remote_host) - 1] = '\0';
    argi++;

    if (argi >= argc)
        nc_bail(ctx, "no port[s] to connect to");

    bool any_success = false;
    int exit_code = 0;
    bool reverse_checked = false;
    bool have_reverse = false;
    bool mismatch_warned = false;
    char reverse_host[NI_MAXHOST] = {0};

    for (int i = argi; i < argc; i++) {
        if (nc_parse_port_range(ctx, argv[i]) < 0)
            nc_bail(ctx, "invalid port %s", argv[i]);

        unsigned short lo = ctx->loport;
        unsigned short hi = ctx->hiport;
        unsigned short cur;

        if (ctx->random_ports && !ctx->single_mode) {
            if (nc_random_ports_init(ctx, lo, hi) < 0)
                nc_bail(ctx, "Can't set up random port list");
            cur = nc_random_ports_next(ctx);
        }
        else {
            cur = hi;
        }

        while (cur && cur >= lo) {
            ctx->curport = cur;
            ctx->port_num = cur;
            char service[16];
            snprintf(service, sizeof(service), "%u", cur);
            (void)nc_resolve_port(ctx, service);

            if (nc_resolve_one(ctx->remote_host, service, ctx->addr_family, ctx->proto, &ctx->remote_addr,
                               &ctx->remote_addrlen, ctx->numeric_only) < 0) {
                nc_holler(ctx, "Could not resolve %s", ctx->remote_host);
                exit_code = 1;
                goto next_port;
            }

            if (ctx->verbose && !ctx->numeric_only && !reverse_checked) {
                reverse_checked = true;
                if (nc_reverse_name((const struct sockaddr*)&ctx->remote_addr, ctx->remote_addrlen, reverse_host,
                                    sizeof(reverse_host), false) == 0) {
                    have_reverse = true;
                    if (!mismatch_warned &&
                        nc_forward_reverse_mismatch(&ctx->remote_addr, ctx->remote_addrlen, reverse_host)) {
                        mismatch_warned = true;
                        nc_holler(ctx, "DNS fwd/rev mismatch: %s != %s", ctx->remote_host, reverse_host);
                    }
                }
            }

            unsigned short saved_local = ctx->ourport;
            if (ctx->random_ports && ctx->ourport == 0) {
                unsigned short rp = (unsigned short)(rand() & 0xffff);
                if (rp < 8192)
                    rp = (unsigned short)(rp + 8192);
                ctx->ourport = rp;
            }

            int fd = nc_connect(ctx);
            ctx->ourport = saved_local;
            if (fd > 0) {
                if (ctx->zero_io && ctx->proto == NC_UDP)
                    fd = nc_udp_test(ctx, fd);

                if (fd > 0) {
                    any_success = true;
                    char numeric_target[NI_MAXHOST];
                    format_addr(&ctx->remote_addr, ctx->remote_addrlen, true, numeric_target, sizeof(numeric_target));
                    const char* display_host = ctx->remote_host;
                    if (!ctx->numeric_only && have_reverse) {
                        display_host = reverse_host;
                    }
                    if (ctx->verbose) {
                        const char* pname = ctx->port_name[0] ? ctx->port_name : "?";
                        nc_holler(ctx, "%s %s %u (%s) open", display_host, numeric_target, cur, pname);
                    }

#ifdef GAPING_SECURITY_HOLE
                    if (ctx->exec_prog) {
                        nc_exec_after_connect(ctx, fd);
                    }
#endif
                    if (!ctx->zero_io) {
                        struct io_buf to_net = {0}, to_out = {0};
                        int rc = nc_pump_io(ctx, fd, &to_net, &to_out);
                        if (rc != 0)
                            exit_code = rc;
                    }
                    else {
                        close(fd);
                    }
                }
                else {
                    exit_code = 1;
                }
            }
            else {
                if (ctx->verbose && (ctx->single_mode || ctx->verbose > 1 || errno != ECONNREFUSED)) {
                    const char* pname = ctx->port_name[0] ? ctx->port_name : "?";
                    nc_holler(ctx, "%s %u (%s) closed", ctx->remote_host, cur, pname);
                }
                exit_code = 1;
            }

            if (ctx->interval)
                sleep(ctx->interval);

        next_port:
            if (ctx->random_ports && !ctx->single_mode) {
                cur = nc_random_ports_next(ctx);
            }
            else {
                if (cur <= lo)
                    break;
                cur--;
            }
        }
    }

    if (!any_success && exit_code == 0)
        exit_code = 1;

    return exit_code;
}

int main(int argc, char** argv) {
    struct nc_ctx ctx;
    nc_ctx_init(&ctx);

    int opt;
    opterr = 0;

    while ((opt = getopt(argc, argv, "46abc:e:hi:lno:p:q:rs:tuvw:z")) != -1) {
        switch (opt) {
            case '4':
                ctx.addr_family = AF_INET;
                break;
            case '6':
#if NC_HAVE_IPV6
                ctx.addr_family = AF_INET6;
#else
                nc_bail(&ctx, "IPv6 support not compiled in");
#endif
                break;
            case 'a':
                nc_bail(&ctx, "all-A-records (-a) not yet implemented");
                break;
            case 'b':
                ctx.allow_broadcast = true;
                break;
#ifdef GAPING_SECURITY_HOLE
            case 'c':
                ctx.exec_prog = optarg;
                ctx.exec_use_sh = true;
                break;
            case 'e':
                ctx.exec_prog = optarg;
                ctx.exec_use_sh = false;
                break;
#else
            case 'c':
            case 'e':
                nc_bail(&ctx, "Exec feature (-e/-c) not enabled at compile time");
                break;
#endif
            case 'h':
                show_help(&ctx);
                break;
            case 'i':
                ctx.interval = (unsigned int)atoi(optarg);
                if (ctx.interval == 0)
                    nc_bail(&ctx, "invalid interval time %s", optarg);
                break;
            case 'l':
                ctx.listen_mode = true;
                break;
            case 'n':
                ctx.numeric_only = true;
                break;
            case 'o':
                ctx.hexdump_enabled = true;
                ctx.hexdump_path = optarg;
                break;
            case 'p': {
                unsigned long val = strtoul(optarg, NULL, 10);
                if (val == 0 || val > 65535)
                    nc_bail(&ctx, "invalid local port %s", optarg);
                ctx.ourport = (unsigned short)val;
                break;
            }
            case 'q':
                ctx.quit_after_eof = atoi(optarg);
                if (ctx.quit_after_eof < 0)
                    nc_bail(&ctx, "invalid quit time %s", optarg);
                break;
            case 'r':
                ctx.random_ports = true;
                break;
            case 's':
                if (nc_resolve_local_address(&ctx, optarg) < 0) {
                    nc_bail(&ctx, "Can't resolve local address %s", optarg);
                }
                break;
#ifdef TELNET
            case 't':
                ctx.telnet = true;
                break;
#else
            case 't':
                nc_bail(&ctx, "TELNET negotiation (-t) not compiled in");
                break;
#endif
            case 'u':
                ctx.proto = NC_UDP;
                break;
            case 'v':
                ctx.verbose++;
                break;
            case 'w':
                ctx.timeout = (unsigned int)atoi(optarg);
                if (ctx.timeout == 0)
                    nc_bail(&ctx, "invalid wait-time %s", optarg);
                break;
            case 'z':
                ctx.zero_io = true;
                break;
            case '?':
                if (optopt == 'c' || optopt == 'e' || optopt == 'p' || optopt == 'i' || optopt == 'w' ||
                    optopt == 'q' || optopt == 'o') {
                    nc_bail(&ctx, "Option -%c requires an argument", optopt);
                }
                else if (optopt == 'g' || optopt == 'G') {
                    nc_bail(&ctx, "Source routing options (-g/-G) have been removed");
                }
                else {
                    nc_bail(&ctx, "Invalid option -%c", optopt);
                }
                break;
            default:
                nc_bail(&ctx, "Unknown error in option parsing");
        }
    }

#ifdef GAPING_SECURITY_HOLE
    if (ctx.exec_prog) {
        ctx.hexdump_enabled = false;
        ctx.hexdump_path = NULL;
    }
#endif

    if (ctx.hexdump_enabled && ctx.hexdump_path) {
        ctx.hexdump_fd = open(ctx.hexdump_path, O_WRONLY | O_CREAT | O_TRUNC, 0664);
        if (ctx.hexdump_fd < 0)
            nc_bail(&ctx, "can't open %s", ctx.hexdump_path);
    }

    setup_signals(&ctx);

    if (!ctx.buf_stdin) {
        ctx.buf_stdin = malloc(NC_BIGSIZ);
        if (!ctx.buf_stdin)
            nc_bail(&ctx, "Failed to allocate stdin buffer");
    }
    if (!ctx.buf_net) {
        ctx.buf_net = malloc(NC_BIGSIZ);
        if (!ctx.buf_net)
            nc_bail(&ctx, "Failed to allocate network buffer");
    }

    if (ctx.random_ports) {
        srand((unsigned int)time(NULL));
    }

    int exit_code;
    if (ctx.listen_mode)
        exit_code = run_listen(&ctx, argc, argv, optind);
    else
        exit_code = run_connect(&ctx, argc, argv, optind);

    if (ctx.verbose > 1) {
        nc_holler(&ctx, "sent %lu, rcvd %lu", (unsigned long)ctx.wrote_net, (unsigned long)ctx.wrote_out);
    }

    nc_ctx_cleanup(&ctx);
    return exit_code;
}
