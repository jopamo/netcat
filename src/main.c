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

// Function declarations
static void parse_arguments(struct nc_ctx* ctx, int argc, char** argv, int* out_optind);
static void setup_signals(void);
static void show_help(struct nc_ctx* ctx);

// Signal handler for interrupts
static void catch_signal(int sig) {
    (void)sig;
    // Will be handled by context cleanup
    _exit(1);
}

int main(int argc, char** argv) {
    struct nc_ctx ctx;
    int exit_code = 0;

    nc_ctx_init(&ctx);

    // Parse command line arguments
    int optind_val;
    parse_arguments(&ctx, argc, argv, &optind_val);

    // Process remaining arguments
    if (optind_val < argc) {
        if (!ctx.listen_mode) {
            // Connect mode: host port [port ...]
            strncpy(ctx.remote_host, argv[optind_val], sizeof(ctx.remote_host) - 1);
            ctx.remote_host[sizeof(ctx.remote_host) - 1] = '\0';
            optind_val++;
            if (optind_val < argc) {
                // Parse first port argument
                if (nc_parse_port_range(&ctx, argv[optind_val]) < 0) {
                    nc_bail(&ctx, "Invalid port %s", argv[optind_val]);
                }
                optind_val++;
                // TODO: handle multiple port arguments
            }
            else {
                nc_bail(&ctx, "Missing port argument");
            }
        }
        else {
            // Listen mode: optional host and port
            // Not yet implemented
        }
    }

    // Setup signal handlers
    setup_signals();

    // Allocate buffers if needed
    if (!ctx.buf_stdin) {
        ctx.buf_stdin = malloc(NC_BIGSIZ);
        if (!ctx.buf_stdin) {
            nc_bail(&ctx, "Failed to allocate stdin buffer");
        }
    }
    if (!ctx.buf_net) {
        ctx.buf_net = malloc(NC_BIGSIZ);
        if (!ctx.buf_net) {
            nc_bail(&ctx, "Failed to allocate network buffer");
        }
    }

    // Open hexdump file if -o specified
    if (ctx.hexdump_enabled) {
        // TODO: open file
        nc_bail(&ctx, "Hexdump (-o) not yet implemented");
    }

    // Random seed if random ports
    if (ctx.random_ports) {
        srand(time(NULL));
    }

    // Determine operation mode
    if (ctx.listen_mode) {
        // Listen mode
        if (ctx.remote_host[0] == '\0') {
            // No host specified, listen on any
        }
        else {
            // Resolve remote host for validation of incoming connections
        }
        // Resolve local address if -s specified
        // Determine port
        if (ctx.ourport == 0) {
            // Need a port to listen on
            nc_bail(&ctx, "Listen mode requires a port (use -p or argument)");
        }
        // TODO: implement listen mode
        nc_bail(&ctx, "Listen mode not yet implemented");
    }
    else {
        // Connect mode
        if (ctx.remote_host[0] == '\0') {
            nc_bail(&ctx, "No destination host specified");
        }
        // Resolve remote host
        struct sockaddr_storage remote;
        socklen_t remote_len;
        char service[16];
        snprintf(service, sizeof(service), "%u", ctx.port_num);
        if (nc_resolve_one(ctx.remote_host, service, AF_UNSPEC, ctx.proto, &remote, &remote_len, ctx.numeric_only) <
            0) {
            nc_bail(&ctx, "Could not resolve %s", ctx.remote_host);
        }
        memcpy(&ctx.remote_addr, &remote, remote_len);
        ctx.remote_addrlen = remote_len;

        // Resolve local address if -s specified
        if (ctx.local_addrlen > 0) {
            // Already resolved by parse_arguments? TODO
        }

        // Port scanning loop
        // For now single port
        int netfd = nc_connect(&ctx);
        if (netfd < 0) {
            nc_holler(&ctx, "Connection failed");
            exit_code = 1;
        }
        else {
            nc_holler(&ctx, "Connected to %s port %d", ctx.remote_host, ctx.port_num);
            if (ctx.zero_io && ctx.proto == NC_UDP) {
                netfd = nc_udp_test(&ctx, netfd);
                if (netfd < 0) {
                    nc_holler(&ctx, "UDP port closed");
                    exit_code = 1;
                }
                else {
                    nc_holler(&ctx, "UDP port open");
                }
            }
            if (netfd > 0) {
                // Exec if requested
#ifdef GAPING_SECURITY_HOLE
                if (ctx.exec_prog) {
                    nc_exec_after_connect(&ctx, netfd);
                }
#endif
                if (!ctx.zero_io) {
                    // I/O pumping
                    struct io_buf to_net = {0}, to_out = {0};
                    exit_code = nc_pump_io(&ctx, netfd, &to_net, &to_out);
                }
                close(netfd);
            }
        }
    }

    if (ctx.verbose > 1) {
        nc_holler(&ctx, "sent %lu, rcvd %lu", ctx.wrote_net, ctx.wrote_out);
    }

    nc_ctx_cleanup(&ctx);
    return exit_code;
}

static void parse_arguments(struct nc_ctx* ctx, int argc, char** argv, int* out_optind) {
    int opt;
    int want6 = 0;  // Track IPv6 preference

    // Disable getopt error messages
    opterr = 0;

    while ((opt = getopt(argc, argv, "46abc:e:hi:lno:p:q:rs:tuvw:z")) != -1) {
        switch (opt) {
#ifdef NC_ENABLE_IPV6
            case '4':
                want6 = 0;
                break;
            case '6':
                want6 = 1;
                break;
#else
            case '4':
            case '6':
                nc_bail(ctx, "IPv6 support not compiled in");
                break;
#endif
            case 'a':
                ctx->all_a_records = true;
                nc_bail(ctx, "all-A-records (-a) not yet implemented");
                break;
            case 'b':
                ctx->allow_broadcast = true;
                break;
#ifdef GAPING_SECURITY_HOLE
            case 'c':
                ctx->exec_prog = optarg;
                ctx->exec_use_sh = true;
                break;
            case 'e':
                ctx->exec_prog = optarg;
                ctx->exec_use_sh = false;
                break;
#else
            case 'c':
            case 'e':
                nc_bail(ctx, "Exec feature (-e/-c) not enabled at compile time");
                break;
#endif
            case 'h':
                show_help(ctx);
                break;
            case 'i':
                ctx->interval = atoi(optarg);
                if (ctx->interval == 0) {
                    nc_bail(ctx, "invalid interval time %s", optarg);
                }
                break;
            case 'l':
                ctx->listen_mode = true;
                break;
            case 'n':
                ctx->numeric_only = true;
                break;
            case 'o':
                ctx->hexdump_enabled = true;
                // Store filename for later opening
                ctx->stage = (unsigned char*)optarg;
                break;
            case 'p':
                ctx->ourport = atoi(optarg);
                if (ctx->ourport == 0) {
                    nc_bail(ctx, "invalid local port %s", optarg);
                }
                break;
            case 'q':
                ctx->quit_after_eof = atoi(optarg);
                if (ctx->quit_after_eof < 0) {
                    nc_bail(ctx, "invalid quit time %s", optarg);
                }
                break;
            case 'r':
                ctx->random_ports = true;
                break;
            case 's':
                // Resolve local source address
                if (nc_resolve_local_address(ctx, optarg) < 0) {
                    nc_bail(ctx, "Can't resolve local address %s", optarg);
                }
                break;
#ifdef TELNET
            case 't':
                ctx->telnet = true;
                break;
#else
            case 't':
                nc_bail(ctx, "TELNET negotiation (-t) not compiled in");
                break;
#endif
            case 'u':
                ctx->proto = NC_UDP;
                break;
            case 'v':
                ctx->verbose++;
                break;
            case 'w':
                ctx->timeout = atoi(optarg);
                if (ctx->timeout <= 0) {
                    nc_bail(ctx, "invalid wait-time %s", optarg);
                }
                break;
            case 'z':
                ctx->zero_io = true;
                break;
            case '?':
                if (optopt == 'c' || optopt == 'e') {
                    nc_bail(ctx, "Option -%c requires an argument", optopt);
                }
                else if (optopt == 'g' || optopt == 'G') {
                    nc_bail(ctx, "Source routing options (-g/-G) have been removed");
                }
                else {
                    nc_bail(ctx, "Invalid option -%c", optopt);
                }
                break;
            default:
                nc_bail(ctx, "Unknown error in option parsing");
        }
    }

    *out_optind = optind;
}

static void setup_signals(void) {
    signal(SIGINT, catch_signal);
    signal(SIGQUIT, catch_signal);
    signal(SIGTERM, catch_signal);
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