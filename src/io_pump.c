#include "io_pump.h"
#include "hexdump.h"
#include "telnet.h"
#include "connect.h"

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>

static bool buf_empty(const struct io_buf* b) {
    return !b || b->len == 0;
}

static void buf_reset(struct io_buf* b) {
    if (!b)
        return;
    b->len = 0;
    b->off = 0;
}

static ssize_t buf_read_into(int fd, struct io_buf* b) {
    if (!b || b->len != 0)
        return 0;

    for (;;) {
        ssize_t r = read(fd, b->data, b->cap);
        if (r < 0 && errno == EINTR)
            continue;
        if (r > 0) {
            b->len = (size_t)r;
            b->off = 0;
        }
        return r;
    }
}

static ssize_t buf_write_from(int fd, struct io_buf* b) {
    if (!b || buf_empty(b))
        return 0;

    size_t remaining = b->len - b->off;
    for (;;) {
        ssize_t w = write(fd, b->data + b->off, remaining);
        if (w < 0 && errno == EINTR)
            continue;
        if (w > 0) {
            b->off += (size_t)w;
            if (b->off >= b->len)
                buf_reset(b);
        }
        return w;
    }
}

static bool timespec_reached(const struct timespec* target, const struct timespec* now) {
    return target->tv_sec < now->tv_sec || (target->tv_sec == now->tv_sec && target->tv_nsec <= now->tv_nsec);
}

static int ms_until(const struct timespec* target, const struct timespec* now) {
    time_t sec = target->tv_sec - now->tv_sec;
    long nsec = target->tv_nsec - now->tv_nsec;
    if (sec < 0 || (sec == 0 && nsec <= 0))
        return 0;

    long ms = sec * 1000 + nsec / 1000000;
    if (ms > INT_MAX)
        return INT_MAX;
    return (int)ms;
}

static void add_seconds(struct timespec* ts, unsigned int seconds) {
    ts->tv_sec += (time_t)seconds;
}

enum timeout_reason {
    TIMEOUT_NONE,
    TIMEOUT_IO,
    TIMEOUT_SEND_DELAY,
    TIMEOUT_QUIT,
};

int nc_pump_io(struct nc_ctx* ctx, int netfd, struct io_buf* to_net, struct io_buf* to_out) {
    bool stdin_open = true;
    bool send_delay_active = false;
    bool quit_deadline_active = false;
    struct timespec send_resume = {0, 0};
    struct timespec quit_deadline = {0, 0};

    int exit_code = 0;

    if (!to_net->data) {
        to_net->data = ctx->buf_stdin ? ctx->buf_stdin : malloc(NC_BIGSIZ);
        to_net->cap = NC_BIGSIZ;
        to_net->len = 0;
        to_net->off = 0;
        if (!ctx->buf_stdin)
            ctx->buf_stdin = to_net->data;
    }
    if (!to_out->data) {
        to_out->data = ctx->buf_net ? ctx->buf_net : malloc(NC_BIGSIZ);
        to_out->cap = NC_BIGSIZ;
        to_out->len = 0;
        to_out->off = 0;
        if (!ctx->buf_net)
            ctx->buf_net = to_out->data;
    }

    if (ctx->insaved > 0 && ctx->buf_stdin) {
        to_net->len = ctx->insaved;
        to_net->off = 0;
        if (ctx->single_mode) {
            ctx->insaved = 0;
        }
        else {
            stdin_open = false;
            close(STDIN_FILENO);
        }
    }

    while (exit_code == 0) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);

        if (ctx->got_signal) {
            exit_code = 128 + (int)ctx->got_signal;
            break;
        }

        if (send_delay_active && timespec_reached(&send_resume, &now))
            send_delay_active = false;

        if (quit_deadline_active && timespec_reached(&quit_deadline, &now))
            break;

        struct pollfd pfds[3];
        nfds_t n = 0;

        // Network fd
        pfds[n].fd = netfd;
        pfds[n].events = 0;
        pfds[n].revents = 0;
        if (to_out->len == 0)
            pfds[n].events |= POLLIN;
        if (to_net->len > 0 && !send_delay_active)
            pfds[n].events |= POLLOUT;
        n++;

        // Stdin
        if (stdin_open && to_net->len == 0) {
            pfds[n].fd = STDIN_FILENO;
            pfds[n].events = POLLIN;
            pfds[n].revents = 0;
            n++;
        }

        // Stdout
        if (to_out->len > 0) {
            pfds[n].fd = STDOUT_FILENO;
            pfds[n].events = POLLOUT;
            pfds[n].revents = 0;
            n++;
        }

        enum timeout_reason reason = TIMEOUT_NONE;
        int timeout_ms = -1;
        if (ctx->timeout > 0) {
            timeout_ms = (int)(ctx->timeout * 1000);
            reason = TIMEOUT_IO;
        }
        if (send_delay_active) {
            int ms = ms_until(&send_resume, &now);
            if (timeout_ms < 0 || ms < timeout_ms) {
                timeout_ms = ms;
                reason = TIMEOUT_SEND_DELAY;
            }
        }
        if (quit_deadline_active) {
            int ms = ms_until(&quit_deadline, &now);
            if (timeout_ms < 0 || ms < timeout_ms) {
                timeout_ms = ms;
                reason = TIMEOUT_QUIT;
            }
        }

        int prc = poll(pfds, n, timeout_ms);
        if (prc < 0) {
            if (errno == EINTR)
                continue;
            exit_code = 1;
            break;
        }
        if (prc == 0) {
            if (reason == TIMEOUT_SEND_DELAY) {
                send_delay_active = false;
                continue;
            }
            if (reason == TIMEOUT_QUIT)
                break;
            if (reason == TIMEOUT_IO) {
                errno = ETIMEDOUT;
                exit_code = 1;
                break;
            }
            continue;
        }

        nfds_t idx = 0;
        struct pollfd* net_pfd = &pfds[idx++];
        bool net_hup = (net_pfd->revents & POLLHUP) != 0;
        bool net_err = (net_pfd->revents & (POLLERR | POLLNVAL)) != 0;
        struct pollfd* in_pfd = NULL;
        struct pollfd* out_pfd = NULL;

        if (net_err) {
            exit_code = 1;
            break;
        }

        if (stdin_open && to_net->len == 0)
            in_pfd = &pfds[idx++];
        if (to_out->len > 0)
            out_pfd = &pfds[idx++];

        // Network readable
        if (net_pfd->revents & POLLIN) {
            ssize_t r = buf_read_into(netfd, to_out);
            if (r == 0) {
                break;  // remote closed
            }
            else if (r < 0) {
                if (errno != EINTR)
                    exit_code = 1;
            }
            else {
#ifdef TELNET
                if (ctx->telnet && to_out->len > 0)
                    nc_telnet_negotiate(ctx, netfd, to_out->data, to_out->len);
#endif
                if (ctx->hexdump_enabled && ctx->hexdump_fd > 0)
                    nc_hexdump_log(ctx, 1, to_out->data, to_out->len);
            }
        }

        // Network writable
        if (!net_hup && (net_pfd->revents & POLLOUT) && to_net->len > 0 && !send_delay_active) {
            const unsigned char* start = to_net->data + to_net->off;
            size_t remaining = to_net->len - to_net->off;
            if (ctx->interval > 0) {
                const unsigned char* nl = memchr(start, '\n', remaining);
                if (nl)
                    remaining = (size_t)(nl - start + 1);
            }

            ssize_t w = nc_send_no_sigpipe(netfd, start, remaining);
            if (w > 0) {
                if (ctx->hexdump_enabled && ctx->hexdump_fd > 0)
                    nc_hexdump_log(ctx, 0, start, (size_t)w);
                to_net->off += (size_t)w;
                ctx->wrote_net += (uint64_t)w;
                if (to_net->off >= to_net->len)
                    buf_reset(to_net);

                if (ctx->interval > 0) {
                    clock_gettime(CLOCK_MONOTONIC, &send_resume);
                    add_seconds(&send_resume, ctx->interval);
                    send_delay_active = true;
                }
            }
            else if (w < 0 && errno != EINTR) {
                exit_code = 1;
            }
        }

        // Stdout writable
        if (out_pfd && (out_pfd->revents & POLLOUT)) {
            ssize_t w = buf_write_from(STDOUT_FILENO, to_out);
            if (w > 0) {
                ctx->wrote_out += (uint64_t)w;
            }
            else if (w < 0 && errno != EINTR) {
                exit_code = 1;
            }
        }

        // Stdin readable / EOF
        if (in_pfd && (in_pfd->revents & (POLLIN | POLLHUP))) {
            ssize_t r = buf_read_into(STDIN_FILENO, to_net);
            if (r > 0) {
                if (!ctx->single_mode) {
                    ctx->insaved = (unsigned int)r;
                    stdin_open = false;
                    close(STDIN_FILENO);
                }
            }
            else if (r == 0) {
                stdin_open = false;
                shutdown(netfd, SHUT_WR);
                if (ctx->quit_after_eof == 0) {
                    break;
                }
                else if (ctx->quit_after_eof > 0) {
                    clock_gettime(CLOCK_MONOTONIC, &quit_deadline);
                    add_seconds(&quit_deadline, (unsigned int)ctx->quit_after_eof);
                    quit_deadline_active = true;
                }
            }
            else if (errno != EINTR) {
                exit_code = 1;
            }
        }

        if (net_hup) {
            stdin_open = false;
            buf_reset(to_net);
            if (buf_empty(to_out))
                break;
        }
    }

    close(netfd);
    ctx->netfd = -1;
    return exit_code;
}
