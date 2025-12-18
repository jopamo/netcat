#include "telnet.h"
#include "nc_ctx.h"

#include <assert.h>
#include <string.h>
#include <unistd.h>

static void test_telnet_replies_cover_will_and_do(void) {
    int fds[2];
    assert(pipe(fds) == 0);

    struct nc_ctx ctx;
    nc_ctx_init(&ctx);

    const unsigned char payload[] = {
        'A', 255, 253, 1,  // IAC DO 1 -> WONT 1
        255, 251, 3,       // IAC WILL 3 -> DONT 3
        255                // trailing IAC without enough bytes should be ignored
    };

    nc_telnet_negotiate(&ctx, fds[1], payload, sizeof(payload));
    close(fds[1]);

    unsigned char replies[16];
    ssize_t n = read(fds[0], replies, sizeof(replies));
    assert(n == 6);
    close(fds[0]);

    const unsigned char expected[] = {255, 252, 1, 255, 254, 3};
    assert(memcmp(replies, expected, sizeof(expected)) == 0);

    nc_ctx_cleanup(&ctx);
}

int main(void) {
    test_telnet_replies_cover_will_and_do();
    return 0;
}
