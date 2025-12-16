#ifndef EXEC_H
#define EXEC_H

#include "nc_ctx.h"

__attribute__((noreturn)) void nc_exec_after_connect(struct nc_ctx* ctx, int netfd);

#endif  // EXEC_H