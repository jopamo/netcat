#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void report_args(int argc, char** argv) {
    printf("argv:");
    for (int i = 0; i < argc; i++) {
        printf("%s%s", (i == 0) ? "" : " ", argv[i]);
    }
    printf("\n");
}

static void report_fd(void) {
    const char* env = getenv("CHECK_FD");
    if (!env || env[0] == '\0')
        return;

    char* end = NULL;
    long fd = strtol(env, &end, 10);
    if (!end || *end != '\0' || fd < 0 || fd > INT_MAX)
        return;

    int rc = fcntl((int)fd, F_GETFD);
    printf("fd:%ld:%s\n", fd, rc >= 0 ? "open" : "closed");
}

static void report_signal_state(const char* name, int signo, const char* envvar) {
    const char* env = getenv(envvar);
    if (!env || env[0] == '\0')
        return;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    if (sigaction(signo, NULL, &sa) != 0)
        return;

    const char* disp = (sa.sa_handler == SIG_IGN) ? "IGN" : (sa.sa_handler == SIG_DFL ? "DFL" : "OTHER");

    sigset_t mask;
    sigemptyset(&mask);
    (void)sigprocmask(SIG_BLOCK, NULL, &mask);
    const char* blocked = sigismember(&mask, signo) ? "blocked" : "unblocked";

    printf("%s:%s:%s\n", name, disp, blocked);
}

int main(int argc, char** argv) {
    bool stay_alive = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "stay") == 0)
            stay_alive = true;
    }

    report_args(argc, argv);
    report_fd();
    report_signal_state("sigusr1", SIGUSR1, "REPORT_SIGUSR1");
    report_signal_state("sigpipe", SIGPIPE, "REPORT_SIGPIPE");
    fflush(stdout);

    if (stay_alive) {
        printf("ready\n");
        fflush(stdout);
        for (;;) {
            pause();
        }
    }

    return 0;
}
