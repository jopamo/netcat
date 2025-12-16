#ifndef TELNET_H
#define TELNET_H

#include "nc_ctx.h"

void nc_telnet_negotiate(struct nc_ctx* ctx, int netfd, const unsigned char* buf, size_t len);

#endif  // TELNET_H