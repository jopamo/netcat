#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdbool.h>

#include "nc_ctx.h"
#include "resolve.h"

static int determine_family(struct nc_ctx* ctx) {
    if (ctx->addr_family == AF_INET)
        return AF_INET;
#if NC_HAVE_IPV6
    if (ctx->addr_family == AF_INET6)
        return AF_INET6;
    if (ctx->remote_addrlen && ctx->remote_addr.ss_family == AF_INET6)
        return AF_INET6;
    if (ctx->local_addrlen && ctx->local_addr.ss_family == AF_INET6)
        return AF_INET6;
#endif
    return AF_INET;
}

static void default_bind_addr(struct nc_ctx* ctx, int family, struct sockaddr_storage* out, socklen_t* outlen) {
    memset(out, 0, sizeof(*out));
    if (family == AF_INET) {
        struct sockaddr_in* sin = (struct sockaddr_in*)out;
        sin->sin_family = AF_INET;
        sin->sin_port = htons(ctx->ourport);
        sin->sin_addr.s_addr = htonl(INADDR_ANY);
        *outlen = sizeof(struct sockaddr_in);
    }
#if NC_HAVE_IPV6
    else if (family == AF_INET6) {
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)out;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(ctx->ourport);
        sin6->sin6_addr = in6addr_any;
        *outlen = sizeof(struct sockaddr_in6);
    }
#endif
}

int nc_connect_with_timeout(int fd, const struct sockaddr* sa, socklen_t slen, int timeout_secs) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;

    int rc = connect(fd, sa, slen);
    if (rc == 0)
        goto done;

    if (errno != EINPROGRESS)
        return -1;

    struct pollfd pfd = {0};
    pfd.fd = fd;
    pfd.events = POLLOUT;

    int ms = (timeout_secs > 0) ? timeout_secs * 1000 : -1;
    int prc = poll(&pfd, 1, ms);
    if (prc <= 0) {
        if (prc == 0)
            errno = ETIMEDOUT;
        return -1;
    }

    int soerr = 0;
    socklen_t olen = sizeof(soerr);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &olen) < 0)
        return -1;
    if (soerr != 0) {
        errno = soerr;
        return -1;
    }

done:
    (void)fcntl(fd, F_SETFL, flags);
    return 0;
}

// Create socket according to ctx->proto and set common options
static int create_socket(struct nc_ctx* ctx) {
    int domain = determine_family(ctx);
    int type = ctx->proto == NC_UDP ? SOCK_DGRAM : SOCK_STREAM;
    int protocol = ctx->proto == NC_UDP ? IPPROTO_UDP : IPPROTO_TCP;

    int fd = socket(domain, type, protocol);
    if (fd < 0)
        return -1;

    // Set SO_REUSEADDR
    int opt = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    // SO_REUSEPORT if available
#ifdef SO_REUSEPORT
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
    // SO_BROADCAST if needed
#ifdef SO_BROADCAST
    if (ctx->allow_broadcast) {
        (void)setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
    }
#endif
    return fd;
}

static void record_local_binding(struct nc_ctx* ctx, int fd) {
    struct sockaddr_storage sa;
    socklen_t slen = sizeof(sa);
    if (getsockname(fd, (struct sockaddr*)&sa, &slen) == 0) {
        memcpy(&ctx->local_addr, &sa, slen);
        ctx->local_addrlen = slen;
        ctx->ourport = nc_get_port(&sa);
    }
}

// Bind socket to local address/port from ctx
static int bind_socket(struct nc_ctx* ctx, int fd, bool is_listen) {
    struct sockaddr_storage bind_sa;
    socklen_t bind_len = 0;

    if (ctx->local_addrlen > 0) {
        memcpy(&bind_sa, &ctx->local_addr, ctx->local_addrlen);
        bind_len = ctx->local_addrlen;
    }
    else if (ctx->ourport || is_listen) {
        int family = determine_family(ctx);
        default_bind_addr(ctx, family, &bind_sa, &bind_len);
    }
    else {
        return 0;  // nothing to bind explicitly
    }

    if (ctx->ourport)
        nc_set_port(&bind_sa, ctx->ourport);

    // Try bind a few times for EADDRINUSE
    for (int tries = 0; tries < 4; tries++) {
        if (bind(fd, (struct sockaddr*)&bind_sa, bind_len) == 0) {
            return 0;
        }
        if (errno != EADDRINUSE)
            break;
        sleep(2);
        errno = 0;
    }
    return -1;
}

// Main connect function: establish outgoing connection
int nc_connect(struct nc_ctx* ctx) {
    int fd = create_socket(ctx);
    if (fd < 0) {
        nc_bail(ctx, "Can't get socket");
        return -1;
    }

    if (bind_socket(ctx, fd, false) < 0) {
        close(fd);
        nc_bail(ctx, "Can't bind local port %d", ctx->ourport);
        return -1;
    }

    int rc;
    if (ctx->timeout > 0) {
        rc = nc_connect_with_timeout(fd, (struct sockaddr*)&ctx->remote_addr, ctx->remote_addrlen, ctx->timeout);
    }
    else {
        rc = connect(fd, (struct sockaddr*)&ctx->remote_addr, ctx->remote_addrlen);
    }
    if (rc < 0) {
        close(fd);
        return -1;
    }

    record_local_binding(ctx, fd);
    ctx->netfd = fd;
    return fd;
}

// Listen for incoming connection (TCP) or datagram (UDP)
int nc_listen(struct nc_ctx* ctx) {
    int fd = create_socket(ctx);
    if (fd < 0) {
        nc_bail(ctx, "Can't get socket");
        return -1;
    }

    if (bind_socket(ctx, fd, true) < 0) {
        close(fd);
        nc_bail(ctx, "Can't bind local listener");
        return -1;
    }

    if (ctx->proto == NC_TCP) {
        if (listen(fd, 1) < 0) {
            close(fd);
            nc_bail(ctx, "listen failed");
            return -1;
        }
    }
    else {
        if (ctx->ourport == 0) {
            close(fd);
            nc_bail(ctx, "UDP listen needs -p arg");
            return -1;
        }
    }

    record_local_binding(ctx, fd);
    return fd;
}

static int wait_for_fd(int fd, short events, int timeout_secs) {
    struct pollfd pfd = {.fd = fd, .events = events};
    int ms = (timeout_secs > 0) ? timeout_secs * 1000 : -1;
    int rc = poll(&pfd, 1, ms);
    if (rc == 0)
        errno = ETIMEDOUT;
    return rc;
}

// Accept incoming TCP connection (or first UDP packet)
int nc_accept(struct nc_ctx* ctx, int listen_fd) {
    if (wait_for_fd(listen_fd, POLLIN, ctx->timeout) <= 0)
        return -1;

    if (ctx->proto == NC_UDP) {
        // For UDP, we need to receive a packet and "connect" the socket
        struct sockaddr_storage peer;
        socklen_t peerlen = sizeof(peer);
        unsigned char scratch[1];
        unsigned char* peek = ctx->buf_net ? (unsigned char*)ctx->buf_net : scratch;
        size_t peek_len = ctx->buf_net ? NC_BIGSIZ : sizeof(scratch);

        ssize_t n = recvfrom(listen_fd, peek, peek_len, MSG_PEEK, (struct sockaddr*)&peer, &peerlen);
        if (n < 0)
            return -1;
        if (connect(listen_fd, (struct sockaddr*)&peer, peerlen) < 0)
            return -1;
        memcpy(&ctx->remote_addr, &peer, peerlen);
        ctx->remote_addrlen = peerlen;
        ctx->netfd = listen_fd;
        return listen_fd;  // same fd now connected
    }

    struct sockaddr_storage peer;
    socklen_t peerlen = sizeof(peer);
    int fd = accept(listen_fd, (struct sockaddr*)&peer, &peerlen);
    if (fd < 0)
        return -1;
    close(listen_fd);  // single connection, match original behavior
    memcpy(&ctx->remote_addr, &peer, peerlen);
    ctx->remote_addrlen = peerlen;
    ctx->netfd = fd;
    return fd;
}

// UDP port test (like original udptest)
int nc_udp_test(struct nc_ctx* ctx, int fd) {
    unsigned char probe = ctx->buf_stdin ? ctx->buf_stdin[0] : 0;
    if (write(fd, &probe, 1) != 1) {
        nc_holler(ctx, "udptest first write failed: %s", strerror(errno));
    }

    if (ctx->timeout > 0) {
        sleep(ctx->timeout);
    }
    else {
        sleep(1);
    }

    errno = 0;
    if (write(fd, &probe, 1) == 1) {
        return fd;  // port seems open
    }
    close(fd);
    return -1;
}
