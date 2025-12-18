#include "connect.h"
#include "nc_ctx.h"
#include "resolve.h"

#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static unsigned short pick_port(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    assert(bind(fd, (struct sockaddr*)&sa, sizeof(sa)) == 0);
    socklen_t len = sizeof(sa);
    assert(getsockname(fd, (struct sockaddr*)&sa, &len) == 0);
    unsigned short p = ntohs(sa.sin_port);
    close(fd);
    return p;
}

static void test_udp_accept_locks_peer_and_preserves_datagram(void) {
    struct nc_ctx lctx;
    nc_ctx_init(&lctx);
    lctx.proto = NC_UDP;
    lctx.addr_family = AF_INET;
    lctx.ourport = pick_port();

    int lfd = nc_listen(&lctx);
    assert(lfd >= 0);

    int cfd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(cfd >= 0);

    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dst.sin_port = htons(lctx.ourport);
    assert(connect(cfd, (struct sockaddr*)&dst, sizeof(dst)) == 0);

    struct sockaddr_in client;
    socklen_t clen = sizeof(client);
    assert(getsockname(cfd, (struct sockaddr*)&client, &clen) == 0);

    const char* msg = "hi";
    assert(send(cfd, msg, 2, 0) == 2);

    int afd = nc_accept(&lctx, lfd);
    assert(afd == lfd);
    assert(lctx.netfd == lfd);

    unsigned char buf[4] = {0};
    ssize_t n = recv(lctx.netfd, buf, sizeof(buf), 0);
    assert(n == 2);
    assert(memcmp(buf, msg, 2) == 0);

    assert(nc_get_port(&lctx.remote_addr) == ntohs(client.sin_port));

    close(cfd);
    nc_ctx_cleanup(&lctx);
}

int main(void) {
    test_udp_accept_locks_peer_and_preserves_datagram();
    return 0;
}
