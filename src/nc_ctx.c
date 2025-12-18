#include "nc_ctx.h"
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

// Initialize context with default values
void nc_ctx_init(struct nc_ctx* ctx) {
    memset(ctx, 0, sizeof(*ctx));

    // Default values matching original globals
    ctx->netfd = -1;
    ctx->hexdump_fd = 0;
    ctx->proto = NC_TCP;
    ctx->listen_mode = false;
    ctx->addr_family = AF_UNSPEC;
    ctx->numeric_only = false;
    ctx->verbose = 0;
    ctx->allow_broadcast = false;
    ctx->zero_io = false;
    ctx->telnet = false;
    ctx->hexdump_enabled = false;
    ctx->hexdump_path = NULL;
    ctx->random_ports = false;
    ctx->all_a_records = false;
    ctx->holler_to_stderr = true;
    ctx->interval = 0;
    ctx->timeout = 0;
    ctx->quit_after_eof = -1;  // -1 = disabled (original o_quit default)
    ctx->wrote_out = 0;
    ctx->wrote_net = 0;
    ctx->hexdump_sent_off = 0;
    ctx->hexdump_recv_off = 0;
    ctx->exec_prog = NULL;
    ctx->exec_use_sh = false;
    ctx->single_mode = true;  // original Single = 1
    ctx->insaved = 0;
    ctx->loport = 0;
    ctx->hiport = 0;
    ctx->curport = 0;
    ctx->ourport = 0;
    ctx->randports = NULL;
    ctx->buf_stdin = NULL;
    ctx->buf_net = NULL;
    ctx->stage = NULL;
    memset(ctx->hexnibs, 0, sizeof(ctx->hexnibs));
    memcpy(ctx->hexnibs, "0123456789abcdef  ", sizeof("0123456789abcdef  ") - 1);
    memset(&ctx->local_addr, 0, sizeof(ctx->local_addr));
    memset(&ctx->remote_addr, 0, sizeof(ctx->remote_addr));
    ctx->local_addrlen = 0;
    ctx->remote_addrlen = 0;
    memset(ctx->remote_host, 0, NC_MAXHOSTNAMELEN);
    memset(ctx->remote_service, 0, 64);
    ctx->expect_peer = false;
    memset(&ctx->expected_peer, 0, sizeof(ctx->expected_peer));
    ctx->expected_peer_len = 0;
    ctx->expected_port = 0;
    memset(ctx->port_name, 0, 64);
    ctx->port_num = 0;
    ctx->log_out = NULL;
    ctx->to_net_buf = NULL;
    ctx->to_out_buf = NULL;
    ctx->got_signal = 0;
    ctx->quit_flag = 0;
}

// Clean up context (free allocated memory)
void nc_ctx_cleanup(struct nc_ctx* ctx) {
    if (ctx->randports) {
        free(ctx->randports);
        ctx->randports = NULL;
    }
    if (ctx->buf_stdin) {
        free(ctx->buf_stdin);
        ctx->buf_stdin = NULL;
    }
    if (ctx->buf_net) {
        free(ctx->buf_net);
        ctx->buf_net = NULL;
    }
    if (ctx->stage) {
        free(ctx->stage);
        ctx->stage = NULL;
    }
    if (ctx->netfd >= 0) {
        close(ctx->netfd);
        ctx->netfd = -1;
    }
    if (ctx->hexdump_fd > 0) {
        close(ctx->hexdump_fd);
        ctx->hexdump_fd = 0;
    }
}

// Internal varargs helper (like original holler_v)
static void nc_holler_v(struct nc_ctx* ctx, const char* fmt, va_list args) {
    FILE* out = ctx->holler_to_stderr ? stderr : stdout;
    if (ctx->verbose) {
        vfprintf(out, fmt, args);
        // Note: original also handled h_errno here, but we're using getaddrinfo
        if (errno) {
            fprintf(out, ": %s", strerror(errno));
        }
        else {
            fprintf(out, "\n");
        }
        fflush(out);
    }
}

// Public logging function (like original holler)
void nc_holler(struct nc_ctx* ctx, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    nc_holler_v(ctx, fmt, args);
    va_end(args);
}

// Fatal error function (like original bail)
void nc_bail(struct nc_ctx* ctx, const char* fmt, ...) {
    ctx->verbose = true;  // force verbose output on error
    va_list args;
    va_start(args, fmt);
    nc_holler_v(ctx, fmt, args);
    va_end(args);
    nc_ctx_cleanup(ctx);
    exit(1);
}

// Debug output (if DEBUG defined)
#ifdef DEBUG
void nc_debug(struct nc_ctx* ctx, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
    fflush(stdout);
    sleep(1);
}
#else
void nc_debug(struct nc_ctx* ctx, const char* fmt, ...) {
    (void)ctx;
    (void)fmt;
}
#endif
