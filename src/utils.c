#include "netcat.h"

int strtoport(char* portstr, int udp) {
    struct servent* entry;
    const char* errstr;
    char* proto;
    int port = -1;

    proto = udp ? "udp" : "tcp";

    port = strtonum(portstr, 1, PORT_MAX, &errstr);
    if (errstr == NULL)
        return port;
    if (errno != EINVAL)
        errx(1, "port number %s: %s", errstr, portstr);
    if ((entry = getservbyname(portstr, proto)) == NULL)
        errx(1, "service \"%s\" unknown", portstr);
    return ntohs(entry->s_port);
}

/*
 * build_ports()
 * Build an array of ports in portlist[], listing each port
 * that we should try to connect to.
 */
void build_ports(char* p) {
    char* n;
    int hi, lo, cp;
    int x = 0;

    if (isdigit((unsigned char)*p) && (n = strchr(p, '-')) != NULL) {
        *n = '\0';
        n++;

        /* Make sure the ports are in order: lowest->highest. */
        hi = strtoport(n, uflag);
        lo = strtoport(p, uflag);
        if (lo > hi) {
            cp = hi;
            hi = lo;
            lo = cp;
        }

        /*
         * Initialize portlist with a random permutation.  Based on
         * Knuth, as in ip_randomid() in sys/netinet/ip_id.c.
         */
        if (rflag) {
            for (x = 0; x <= hi - lo; x++) {
                cp = arc4random_uniform(x + 1);
                portlist[x] = portlist[cp];
                if (asprintf(&portlist[cp], "%d", x + lo) == -1)
                    err(1, "asprintf");
            }
        }
        else { /* Load ports sequentially. */
            for (cp = lo; cp <= hi; cp++) {
                if (asprintf(&portlist[x], "%d", cp) == -1)
                    err(1, "asprintf");
                x++;
            }
        }
    }
    else {
        char* tmp;

        hi = strtoport(p, uflag);
        if (asprintf(&tmp, "%d", hi) != -1)
            portlist[0] = tmp;
        else {
            err(1, NULL);
        }
    }
}

#ifdef GAPING_SECURITY_HOLE
void spawn_exec(int net_fd) {
    int pin[2], pout[2];

    if (pipe(pin) == -1 || pipe(pout) == -1)
        err(1, "pipe");

    switch (fork()) {
        case -1:
            err(1, "fork");
        case 0: /* Child */
            close(net_fd);
            if (dup2(pin[0], STDIN_FILENO) == -1)
                err(1, "dup2 child stdin");
            close(pin[0]);
            close(pin[1]);

            if (dup2(pout[1], STDOUT_FILENO) == -1)
                err(1, "dup2 child stdout");
            if (dup2(pout[1], STDERR_FILENO) == -1)
                err(1, "dup2 child stderr");
            close(pout[0]);
            close(pout[1]);

            execl("/bin/sh", "sh", "-c", exec_path, (char*)NULL);
            err(1, "execl");
        default: /* Parent */
            if (dup2(pin[1], STDOUT_FILENO) == -1)
                err(1, "dup2 parent stdout");
            close(pin[0]);
            close(pin[1]);

            if (dup2(pout[0], STDIN_FILENO) == -1)
                err(1, "dup2 parent stdin");
            close(pout[0]);
            close(pout[1]);
    }
}
#endif
