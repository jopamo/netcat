#include "netcat.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/random.h>

uint32_t (*nc_random)(void) = nc_random_u32;

long long nc_strtonum(const char* numstr, long long minval, long long maxval, const char** errstrp) {
    long long ll = 0;
    char* ep;
    int error = 0;
    static const char* const errors[] = {NULL, "invalid", "too small", "too large"};

    if (minval > maxval)
        error = 1;
    else {
        errno = 0;
        ll = strtoll(numstr, &ep, 10);
        if (numstr == ep || *ep != '\0')
            error = 1;
        else if ((ll == LLONG_MIN && errno == ERANGE) || ll < minval)
            error = 2;
        else if ((ll == LLONG_MAX && errno == ERANGE) || ll > maxval)
            error = 3;
    }

    if (errstrp != NULL)
        *errstrp = errors[error];
    if (error)
        return 0;
    return ll;
}

size_t nc_strlcpy(char* dst, const char* src, size_t dsize) {
    size_t srclen = strlen(src);
    if (dsize != 0) {
        size_t copy = srclen >= dsize ? dsize - 1 : srclen;
        memcpy(dst, src, copy);
        dst[copy] = '\0';
    }
    return srclen;
}

static int fill_random(void* buf, size_t len) {
#ifdef __linux__
    unsigned char* p = buf;
    while (len > 0) {
        ssize_t n = getrandom(p, len, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno == ENOSYS)
                break;
            return -1;
        }
        p += (size_t)n;
        len -= (size_t)n;
    }
    if (len == 0)
        return 0;
#endif
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd == -1)
        return -1;
    unsigned char* p = buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        if (n == 0) {
            close(fd);
            return -1;
        }
        p += (size_t)n;
        len -= (size_t)n;
    }
    close(fd);
    return 0;
}

void nc_random_buf(void* buf, size_t len) {
    if (fill_random(buf, len) == 0)
        return;
    static int seeded = 0;
    if (!seeded) {
        seeded = 1;
        srand((unsigned int)time(NULL) ^ (unsigned int)getpid());
    }
    unsigned char* p = buf;
    for (size_t i = 0; i < len; i++)
        p[i] = (unsigned char)(rand() & 0xff);
}

uint32_t nc_random_u32(void) {
    uint32_t v = 0;
    nc_random_buf(&v, sizeof(v));
    return v;
}

uint32_t nc_random_uniform(uint32_t upper_bound) {
    if (upper_bound == 0)
        return 0;
    uint32_t threshold = (uint32_t)(-upper_bound) % upper_bound;
    for (;;) {
        uint32_t r = nc_random_u32();
        if (r >= threshold)
            return r % upper_bound;
    }
}

int strtoport(char* portstr, int udp) {
    struct servent* entry;
    const char* errstr;
    char* proto;
    int port = -1;

    proto = udp ? "udp" : "tcp";

    port = nc_strtonum(portstr, 1, PORT_MAX, &errstr);
    if (errstr == NULL)
        return port;
    if (strcmp(errstr, "invalid") != 0)
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
                cp = (int)nc_random_uniform((uint32_t)(x + 1));
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
