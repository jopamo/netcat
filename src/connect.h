#ifndef CONNECT_H
#define CONNECT_H

#include <sys/socket.h>

struct nc_ctx;

int nc_connect_with_timeout(int fd, const struct sockaddr* sa, socklen_t slen, int timeout_secs);
int nc_connect(struct nc_ctx* ctx);
int nc_listen(struct nc_ctx* ctx);
int nc_accept(struct nc_ctx* ctx, int listen_fd);
int nc_udp_test(struct nc_ctx* ctx, int fd);

#endif  // CONNECT_H