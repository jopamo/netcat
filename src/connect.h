#ifndef CONNECT_H
#define CONNECT_H

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>

struct nc_ctx;

int nc_connect_with_timeout(int fd, const struct sockaddr* sa, socklen_t slen, int timeout_secs);
int nc_connect(struct nc_ctx* ctx);
int nc_listen(struct nc_ctx* ctx);
int nc_accept(struct nc_ctx* ctx, int listen_fd);
int nc_udp_test(struct nc_ctx* ctx, int fd);

static inline ssize_t nc_send_no_sigpipe(int fd, const void* buf, size_t len) {
    int flags = 0;
#ifdef MSG_NOSIGNAL
    flags |= MSG_NOSIGNAL;
#endif
    ssize_t rc;
    do {
        rc = send(fd, buf, len, flags);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0 && (errno == ENOTSOCK || errno == EOPNOTSUPP)) {
        do {
            rc = write(fd, buf, len);
        } while (rc < 0 && errno == EINTR);
    }
    return rc;
}

#endif  // CONNECT_H
