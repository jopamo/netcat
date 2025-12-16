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
#include "nc_ctx.h"
#include "resolve.h"

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
    int domain = AF_INET;  // TODO: IPv6 support
    int type = ctx->proto == NC_UDP ? SOCK_DGRAM : SOCK_STREAM;
    int protocol = ctx->proto == NC_UDP ? IPPROTO_UDP : IPPROTO_TCP;

    int fd = socket(domain, type, protocol);
    if (fd < 0)
        return -1;

    // Set SO_REUSEADDR
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    // SO_REUSEPORT if available
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
    // SO_BROADCAST if needed
#ifdef SO_BROADCAST
    if (ctx->allow_broadcast) {
        setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
    }
#endif
    return fd;
}

// Bind socket to local address/port from ctx
static int bind_socket(struct nc_ctx* ctx, int fd) {
    if (ctx->local_addrlen == 0) {
        // No explicit bind requested
        return 0;
    }
    // Try bind a few times for EADDRINUSE
    for (int tries = 0; tries < 4; tries++) {
        if (bind(fd, (struct sockaddr*)&ctx->local_addr, ctx->local_addrlen) == 0) {
            return 0;
        }
        if (errno != EADDRINUSE)
            break;
        // Wait and retry
        sleep(2);
        errno = 0;
    }
    return -1;
}

// Main connect function: establish outgoing connection
int nc_connect(struct nc_ctx* ctx) {
    // Create socket
    int fd = create_socket(ctx);
    if (fd < 0) {
        nc_bail(ctx, "Can't get socket");
        return -1;
    }

    // Bind local address if specified
    if (bind_socket(ctx, fd) < 0) {
        close(fd);
        nc_bail(ctx, "Can't bind %s:%d", "local", ctx->ourport);  // TODO: format address
        return -1;
    }

    // Connect to remote address
    if (ctx->timeout > 0) {
        if (nc_connect_with_timeout(fd, (struct sockaddr*)&ctx->remote_addr, ctx->remote_addrlen, ctx->timeout) < 0) {
            close(fd);
            return -1;
        }
    }
    else {
        if (connect(fd, (struct sockaddr*)&ctx->remote_addr, ctx->remote_addrlen) < 0) {
            close(fd);
            return -1;
        }
    }
    return fd;
}

// Listen for incoming connection (TCP) or datagram (UDP)
int nc_listen(struct nc_ctx* ctx) {
    int fd = create_socket(ctx);
    if (fd < 0) {
        nc_bail(ctx, "Can't get socket");
        return -1;
    }

    // Bind local address
    if (bind_socket(ctx, fd) < 0) {
        close(fd);
        nc_bail(ctx, "Can't bind %s:%d", "local", ctx->ourport);
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
        // UDP: nothing else needed now
        if (ctx->ourport == 0) {
            nc_bail(ctx, "UDP listen needs -p arg");
            close(fd);
            return -1;
        }
    }
    return fd;
}

// Accept incoming TCP connection (or first UDP packet)
int nc_accept(struct nc_ctx* ctx, int listen_fd) {
    if (ctx->proto == NC_UDP) {
        // For UDP, we need to receive a packet and "connect" the socket
        struct sockaddr_storage peer;
        socklen_t peerlen = sizeof(peer);
        ssize_t n = recvfrom(listen_fd, ctx->buf_net, NC_BIGSIZ, MSG_PEEK, (struct sockaddr*)&peer, &peerlen);
        if (n < 0)
            return -1;
        // Connect the socket to the peer
        if (connect(listen_fd, (struct sockaddr*)&peer, peerlen) < 0)
            return -1;
        // Update remote address in ctx
        memcpy(&ctx->remote_addr, &peer, peerlen);
        ctx->remote_addrlen = peerlen;
        return listen_fd;  // same fd now connected
    }
    else {
        // TCP accept
        struct sockaddr_storage peer;
        socklen_t peerlen = sizeof(peer);
        int fd = accept(listen_fd, (struct sockaddr*)&peer, &peerlen);
        if (fd < 0)
            return -1;
        close(listen_fd);  // original listener no longer needed
        memcpy(&ctx->remote_addr, &peer, peerlen);
        ctx->remote_addrlen = peerlen;
        return fd;
    }
}

// UDP port test (like original udptest)
int nc_udp_test(struct nc_ctx* ctx, int fd) {
    // Send a single byte
    if (write(fd, ctx->buf_stdin, 1) != 1) {
        nc_holler(ctx, "udptest first write failed: %s", strerror(errno));
    }
    if (ctx->timeout > 0) {
        sleep(ctx->timeout);
    }
    else {
        // Use TCP ping trick (omitted for simplicity)
        // For now, just small sleep
        sleep(1);
    }
    errno = 0;
    if (write(fd, ctx->buf_stdin, 1) == 1) {
        return fd;  // port seems open
    }
    close(fd);
    return -1;
}