#ifndef HEXDUMP_H
#define HEXDUMP_H

#include "nc_ctx.h"
#include <stdint.h>

void nc_hexdump_write(int fd, const unsigned char* buf, size_t len, uint64_t base);
void nc_hexdump_log(struct nc_ctx* ctx, int direction, const unsigned char* buf, size_t len);

#endif  // HEXDUMP_H
