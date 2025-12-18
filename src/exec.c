#include "nc_ctx.h"
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/syscall.h>

static void nc_close_fds_keep_stdio(void) {
#if defined(__linux__) && defined(SYS_close_range)
    if (syscall(SYS_close_range, 3U, ~0U, 0U) == 0)
        return;
#endif
    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0)
        maxfd = 1024;
    for (long fd = 3; fd < maxfd; fd++) {
        close((int)fd);
    }
}

static void nc_reset_signals_for_exec(void) {
    const int sigs[] = {SIGINT, SIGQUIT, SIGTERM, SIGPIPE, SIGHUP, SIGUSR1, SIGUSR2};
    for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) {
        (void)signal(sigs[i], SIG_DFL);
    }

    sigset_t empty;
    sigemptyset(&empty);
    (void)sigprocmask(SIG_SETMASK, &empty, NULL);
}

static void dup_stdio_or_exit(int netfd) {
    if (dup2(netfd, STDIN_FILENO) < 0)
        _exit(127);
    if (dup2(netfd, STDOUT_FILENO) < 0)
        _exit(127);
    if (dup2(netfd, STDERR_FILENO) < 0)
        _exit(127);
}

__attribute__((noreturn)) void nc_exec_after_connect(struct nc_ctx* ctx, int netfd) {
    if ((!ctx->exec_prog && !ctx->exec_argv) || netfd < 0)
        _exit(127);

    dup_stdio_or_exit(netfd);
    if (netfd > STDERR_FILENO)
        close(netfd);

    if (ctx->exec_close_fds)
        nc_close_fds_keep_stdio();

    if (ctx->exec_reset_signals)
        nc_reset_signals_for_exec();

    if (ctx->exec_use_sh) {
        char* const argv[] = {"sh", "-c", (char*)ctx->exec_prog, NULL};
        execv("/bin/sh", argv);
        _exit(127);
    }

    if (ctx->exec_argv && ctx->exec_argv[0]) {
        execv(ctx->exec_argv[0], ctx->exec_argv);
        _exit(127);
    }

    if (ctx->exec_prog) {
        char* const argv[] = {(char*)ctx->exec_prog, NULL};
        execv(ctx->exec_prog, argv);
    }

    _exit(127);
}
