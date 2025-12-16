#ifndef IO_PUMP_H
#define IO_PUMP_H

#include "nc_ctx.h"
#include <stdbool.h>
#include <sys/types.h>

struct io_buf {
    unsigned char* data;
    size_t cap;
    size_t len;
    size_t off;
};

int nc_pump_io(struct nc_ctx* ctx, int netfd, struct io_buf* to_net, struct io_buf* to_out);

#endif  // IO_PUMP_H