#include "nc_ctx.h"
#include <unistd.h>
#include <stdlib.h>

__attribute__((noreturn)) void nc_exec_after_connect(struct nc_ctx* ctx, int netfd) {
    if (!ctx->exec_prog)
        _exit(127);

    dup2(netfd, STDIN_FILENO);
    dup2(netfd, STDOUT_FILENO);
    dup2(netfd, STDERR_FILENO);
    close(netfd);

    if (ctx->exec_use_sh) {
        execl("/bin/sh", "sh", "-c", ctx->exec_prog, (char*)0);
        _exit(127);
    }

    // exec_prog is a path; execute it directly
    execl(ctx->exec_prog, ctx->exec_prog, (char*)0);
    _exit(127);
}