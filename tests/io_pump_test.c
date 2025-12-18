#include "io_pump.h"
#include "nc_ctx.h"

#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void test_io_pump_moves_data_both_directions(void) {
    int sp[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);

    int cap[2];
    assert(pipe(cap) == 0);

    pid_t pid = fork();
    assert(pid >= 0);

    if (pid == 0) {
        close(sp[1]);
        close(cap[0]);

        int devnull = open("/dev/null", O_RDONLY);
        assert(devnull >= 0);
        assert(dup2(devnull, STDIN_FILENO) >= 0);
        close(devnull);

        assert(dup2(cap[1], STDOUT_FILENO) >= 0);
        close(cap[1]);

        struct nc_ctx ctx;
        nc_ctx_init(&ctx);

        const char* initial = "hello";
        size_t ilen = strlen(initial);
        ctx.buf_stdin = malloc(ilen);
        assert(ctx.buf_stdin);
        memcpy(ctx.buf_stdin, initial, ilen);
        ctx.insaved = (unsigned int)ilen;
        ctx.single_mode = true;

        struct io_buf to_net = {0};
        struct io_buf to_out = {0};

        int rc = nc_pump_io(&ctx, sp[0], &to_net, &to_out);
        nc_ctx_cleanup(&ctx);
        _exit(rc);
    }

    close(sp[0]);
    close(cap[1]);

    char buf[16];
    ssize_t n = read(sp[1], buf, sizeof(buf));
    assert(n == 5);
    assert(memcmp(buf, "hello", 5) == 0);

    const char* reply = "world";
    assert(write(sp[1], reply, 5) == 5);
    close(sp[1]);

    char out[16];
    ssize_t out_n = read(cap[0], out, sizeof(out));
    assert(out_n == 5);
    assert(memcmp(out, "world", 5) == 0);
    close(cap[0]);

    int status;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == 0);
}

int main(void) {
    test_io_pump_moves_data_both_directions();
    return 0;
}
