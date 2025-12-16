#include "nc_ctx.h"
#include "telnet.h"
#include <poll.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

struct io_buf {
    unsigned char* data;
    size_t cap;
    size_t len;
    size_t off;
};

static bool buf_empty(const struct io_buf* b) {
    return b->off >= b->len;
}

static void buf_reset(struct io_buf* b) {
    b->len = 0;
    b->off = 0;
}

static ssize_t buf_read_into(int fd, struct io_buf* b) {
    if (b->len != 0)
        return 0;
    ssize_t r = read(fd, b->data, b->cap);
    if (r > 0) {
        b->len = (size_t)r;
        b->off = 0;
    }
    return r;
}

static ssize_t buf_write_from(int fd, struct io_buf* b) {
    if (buf_empty(b))
        return 0;
    ssize_t r = write(fd, b->data + b->off, b->len - b->off);
    if (r > 0) {
        b->off += (size_t)r;
        if (buf_empty(b))
            buf_reset(b);
    }
    return r;
}

// Find next newline in buffer (like original findline)
static size_t find_line(const unsigned char* buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == '\n') {
            return i + 1;  // include newline
        }
    }
    return len;  // no newline, send whole buffer
}

int nc_pump_io(struct nc_ctx* ctx, int netfd, struct io_buf* to_net, struct io_buf* to_out) {
    fd_set readfds, writefds;
    int maxfd;
    int stdin_closed = 0;
    int net_closed = 0;
    int exit_code = 0;

    // Initialize buffers if not already
    if (!to_net->data) {
        to_net->data = ctx->buf_stdin ? ctx->buf_stdin : malloc(NC_BIGSIZ);
        to_net->cap = NC_BIGSIZ;
        to_net->len = 0;
        to_net->off = 0;
    }
    if (!to_out->data) {
        to_out->data = ctx->buf_net ? ctx->buf_net : malloc(NC_BIGSIZ);
        to_out->cap = NC_BIGSIZ;
        to_out->len = 0;
        to_out->off = 0;
    }

    // If we have saved stdin buffer from multi-mode
    if (ctx->insaved > 0) {
        // Already loaded into ctx->buf_stdin, simulate read
        to_net->len = ctx->insaved;
        to_net->off = 0;
        if (ctx->single_mode) {
            ctx->insaved = 0;  // one-off
        }
        else {
            // scanning mode, close stdin
            close(STDIN_FILENO);
            stdin_closed = 1;
        }
    }

    // Delay before sending if interval specified
    if (ctx->interval > 0) {
        sleep(ctx->interval);
    }

    while (!net_closed) {
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        maxfd = 0;

        // Setup read fds
        if (!stdin_closed && to_net->len == 0) {
            FD_SET(STDIN_FILENO, &readfds);
            if (STDIN_FILENO > maxfd)
                maxfd = STDIN_FILENO;
        }
        if (!net_closed && to_out->len == 0) {
            FD_SET(netfd, &readfds);
            if (netfd > maxfd)
                maxfd = netfd;
        }

        // Setup write fds
        if (to_net->len > 0) {
            FD_SET(netfd, &writefds);
            if (netfd > maxfd)
                maxfd = netfd;
        }
        if (to_out->len > 0) {
            FD_SET(STDOUT_FILENO, &writefds);
            if (STDOUT_FILENO > maxfd)
                maxfd = STDOUT_FILENO;
        }

        // Timeout handling
        struct timeval timeout, *timeout_ptr = NULL;
        if (ctx->timeout > 0 && stdin_closed) {
            timeout.tv_sec = ctx->timeout;
            timeout.tv_usec = 0;
            timeout_ptr = &timeout;
        }

        int sel = select(maxfd + 1, &readfds, &writefds, NULL, timeout_ptr);
        if (sel < 0) {
            if (errno == EINTR)
                continue;
            nc_holler(ctx, "select error: %s", strerror(errno));
            exit_code = 1;
            break;
        }

        if (sel == 0) {
            // Timeout with stdin closed -> assume net dead
            if (stdin_closed) {
                net_closed = 1;
                break;
            }
        }

        // Read from stdin
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            ssize_t r = read(STDIN_FILENO, to_net->data, to_net->cap);
            if (r > 0) {
                to_net->len = r;
                to_net->off = 0;
                // If scanning mode, save buffer and close stdin
                if (!ctx->single_mode) {
                    ctx->insaved = r;
                    close(STDIN_FILENO);
                    stdin_closed = 1;
                }
            }
            else if (r == 0) {
                // EOF on stdin
                close(STDIN_FILENO);
                stdin_closed = 1;
                if (ctx->quit_after_eof == 0) {
                    // Exit immediately
                    shutdown(netfd, SHUT_WR);
                    close(netfd);
                    net_closed = 1;
                    break;
                }
                else if (ctx->quit_after_eof > 0) {
                    // Schedule quit after delay
                    alarm(ctx->quit_after_eof);
                }
            }
            else {
                nc_holler(ctx, "stdin read error: %s", strerror(errno));
            }
        }

        // Read from net
        if (FD_ISSET(netfd, &readfds)) {
            ssize_t r = read(netfd, to_out->data, to_out->cap);
            if (r > 0) {
                to_out->len = r;
                to_out->off = 0;
                // Telnet negotiation if enabled
#ifdef TELNET
                if (ctx->telnet) {
                    nc_telnet_negotiate(ctx, netfd, to_out->data, r);
                }
#endif
                // Hexdump if enabled
                if (ctx->hexdump_enabled && ctx->hexdump_fd > 0) {
                    // TODO: call hexdump function
                }
            }
            else if (r == 0) {
                // Net closed
                net_closed = 1;
                break;
            }
            else {
                nc_holler(ctx, "net read error: %s", strerror(errno));
            }
        }

        // Write to net
        if (FD_ISSET(netfd, &writefds) && to_net->len > 0) {
            size_t to_write = to_net->len;
            if (ctx->interval > 0) {
                // Send line by line
                to_write = find_line(to_net->data + to_net->off, to_net->len - to_net->off);
            }
            ssize_t w = write(netfd, to_net->data + to_net->off, to_write);
            if (w > 0) {
                to_net->off += w;
                ctx->wrote_net += w;
                if (to_net->off >= to_net->len) {
                    to_net->len = 0;
                    to_net->off = 0;
                }
                // Hexdump if enabled
                if (ctx->hexdump_enabled && ctx->hexdump_fd > 0) {
                    // TODO: call hexdump function
                }
                // If interval, sleep after each line
                if (ctx->interval > 0 && w == (ssize_t)to_write) {
                    sleep(ctx->interval);
                }
            }
            else {
                nc_holler(ctx, "net write error: %s", strerror(errno));
                net_closed = 1;
                break;
            }
        }

        // Write to stdout
        if (FD_ISSET(STDOUT_FILENO, &writefds) && to_out->len > 0) {
            ssize_t w = write(STDOUT_FILENO, to_out->data + to_out->off, to_out->len - to_out->off);
            if (w > 0) {
                to_out->off += w;
                ctx->wrote_out += w;
                if (to_out->off >= to_out->len) {
                    to_out->len = 0;
                    to_out->off = 0;
                }
            }
            else {
                nc_holler(ctx, "stdout write error: %s", strerror(errno));
            }
        }
    }

    close(netfd);
    return exit_code;
}