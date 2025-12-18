#include "nc_ctx.h"
#include "connect.h"
#include <unistd.h>
#include <stdint.h>

void nc_telnet_negotiate(struct nc_ctx* ctx, int netfd, const unsigned char* buf, size_t len) {
    (void)ctx;

    // Minimal logic: when you see IAC (255), respond with DONT/WONT variants
    // Keep behavior compatible with your existing atelnet()
    // Important: do not block; write best-effort

    unsigned char reply[3];
    for (size_t i = 0; i + 2 < len; i++) {
        if (buf[i] != 255)
            continue;

        unsigned char cmd = buf[i + 1];
        unsigned char opt = buf[i + 2];

        unsigned char resp = 0;
        if (cmd == 251 || cmd == 252)       // WILL/WONT
            resp = 254;                     // DONT
        else if (cmd == 253 || cmd == 254)  // DO/DONT
            resp = 252;                     // WONT

        if (resp) {
            reply[0] = 255;
            reply[1] = resp;
            reply[2] = opt;
            (void)nc_send_no_sigpipe(netfd, reply, sizeof(reply));
        }
    }
}
