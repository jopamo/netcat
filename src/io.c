#include "netcat.h"
#include "pcap.h"
#include "syscalls.h"
#include <fcntl.h>
#include <math.h>
#include <signal.h>
#include <sys/mman.h>

static size_t hex_total_in, hex_total_out;

/* Box-Muller transform to generate Gaussian random numbers */
static double gaussian_random(double mean, double stddev) {
    static double V1, V2, S;
    static int phase = 0;
    double X;

    if (phase == 0) {
        do {
            double U1 = (double)arc4random() / UINT32_MAX;
            double U2 = (double)arc4random() / UINT32_MAX;
            V1 = 2 * U1 - 1;
            V2 = 2 * U2 - 1;
            S = V1 * V1 + V2 * V2;
        } while (S >= 1 || S == 0);

        X = V1 * sqrt(-2 * log(S) / S);
    }
    else {
        X = V2 * sqrt(-2 * log(S) / S);
    }

    phase = 1 - phase;
    return X * stddev + mean;
}

static void rolling_xor(const unsigned char* in,
                        size_t len,
                        unsigned char* out,
                        const unsigned char* key,
                        size_t key_len) {
    size_t i;
    for (i = 0; i < len; i++) {
        out[i] = in[i] ^ key[i % key_len];
    }
}

static int base64_encode(const unsigned char* in, size_t in_len, char* out, size_t out_len) {
    static const char set[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char* p = out;
    size_t i;
    int val = 0;
    int valb = -6;

    if (out_len < (in_len * 4 / 3) + 5)
        return -1;

    for (i = 0; i < in_len; i++) {
        val = (val << 8) + in[i];
        valb += 8;
        while (valb >= 0) {
            *p++ = set[(val >> valb) & 0x3F];
            valb -= 6;
        }
    }
    if (valb > -6)
        *p++ = set[((val << 8) >> (valb + 8)) & 0x3F];
    while ((p - out) % 4)
        *p++ = '=';
    *p = 0;
    return p - out;
}

void splice_loop(int net_fd) {
    int p_in[2], p_out[2];
    struct pollfd pfd[4];
    int stdin_fd = STDIN_FILENO;
    int stdout_fd = STDOUT_FILENO;
    int n, num_fds;

    if (pipe(p_in) == -1 || pipe(p_out) == -1)
        err(1, "pipe");

    if (dflag)
        stdin_fd = -1;

    pfd[POLL_STDIN].fd = stdin_fd;
    pfd[POLL_STDIN].events = POLLIN;
    pfd[POLL_NETOUT].fd = net_fd;
    pfd[POLL_NETOUT].events = 0;
    pfd[POLL_NETIN].fd = net_fd;
    pfd[POLL_NETIN].events = POLLIN;
    pfd[POLL_STDOUT].fd = stdout_fd;
    pfd[POLL_STDOUT].events = 0;

    while (1) {
        if (pfd[POLL_STDIN].fd == -1 && pfd[POLL_NETIN].fd == -1)
            return;
        if (pfd[POLL_NETOUT].fd == -1 && pfd[POLL_STDOUT].fd == -1)
            return;

        num_fds = poll(pfd, 4, timeout);
        if (num_fds == -1)
            err(1, "poll");
        if (num_fds == 0)
            return;

        for (n = 0; n < 4; n++) {
            if (pfd[n].revents & (POLLERR | POLLNVAL))
                pfd[n].fd = -1;
        }

        if (pfd[POLL_STDIN].revents & POLLIN) {
            ssize_t s = splice(pfd[POLL_STDIN].fd, NULL, p_in[1], NULL, BUFSIZE, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
            if (s > 0) {
                if (splice(p_in[0], NULL, pfd[POLL_NETOUT].fd, NULL, s, SPLICE_F_MOVE) == -1)
                    pfd[POLL_NETOUT].fd = -1;
            }
            else if (s == 0) {
                pfd[POLL_STDIN].fd = -1;
                if (Nflag)
                    shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
                pfd[POLL_NETOUT].fd = -1;
            }
        }

        if (pfd[POLL_NETIN].revents & POLLIN) {
            ssize_t s = splice(pfd[POLL_NETIN].fd, NULL, p_out[1], NULL, BUFSIZE, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
            if (s > 0) {
                if (splice(p_out[0], NULL, pfd[POLL_STDOUT].fd, NULL, s, SPLICE_F_MOVE) == -1)
                    pfd[POLL_STDOUT].fd = -1;
            }
            else if (s == 0) {
                pfd[POLL_NETIN].fd = -1;
                pfd[POLL_STDOUT].fd = -1;
            }
        }
    }
}

/*
 * readwrite()
 * Loop that polls on the network file descriptor and stdin.
 */
void readwrite(int net_fd, struct tls* tls_ctx) {
    struct pollfd pfd[4];
    int stdin_fd = STDIN_FILENO;
    int stdout_fd = STDOUT_FILENO;
    unsigned char* netinbuf = NULL;
    unsigned char* stdinbuf = NULL;
    size_t netinbufpos = 0;
    size_t stdinbufpos = 0;
    int n, num_fds;
    ssize_t ret;

    /* Use aligned heap memory for mprotect compatibility (Foliage Sleep) */
    if (posix_memalign((void**)&netinbuf, 4096, BUFSIZE))
        err(1, "memalign");
    if (posix_memalign((void**)&stdinbuf, 4096, BUFSIZE))
        err(1, "memalign");

    if (spliceflag && !tls_ctx) {
        free(netinbuf);
        free(stdinbuf);
        splice_loop(net_fd);
        return;
    }

    if (pcapfile)
        pcap_open(net_fd, pcapfile);

    if (hex_path) {
        if (strcmp(hex_path, "-") == 0)
            hex_fp = stderr;
        else if ((hex_fp = fopen(hex_path, "w")) == NULL)
            err(1, "hex-dump");
        hex_total_in = hex_total_out = 0;
    }

    /* don't read from stdin if requested or fuzzing */
    if (dflag || fuzz_tcp || fuzz_udp)
        stdin_fd = -1;

    /* stdin */
    pfd[POLL_STDIN].fd = stdin_fd;
    pfd[POLL_STDIN].events = POLLIN;

    /* network out */
    pfd[POLL_NETOUT].fd = net_fd;
    pfd[POLL_NETOUT].events = 0;

    /* network in */
    pfd[POLL_NETIN].fd = net_fd;
    pfd[POLL_NETIN].events = POLLIN;

    /* stdout */
    pfd[POLL_STDOUT].fd = stdout_fd;
    pfd[POLL_STDOUT].events = 0;

    while (1) {
        /* both inputs are gone, buffers are empty, we are done */
        if (pfd[POLL_STDIN].fd == -1 && pfd[POLL_NETIN].fd == -1 && stdinbufpos == 0 && netinbufpos == 0)
            goto cleanup;
        /* both outputs are gone, we can't continue */
        if (pfd[POLL_NETOUT].fd == -1 && pfd[POLL_STDOUT].fd == -1)
            goto cleanup;
        /* listen and net in gone, queues empty, done */
        if (lflag && pfd[POLL_NETIN].fd == -1 && stdinbufpos == 0 && netinbufpos == 0)
            goto cleanup;

        /* help says -i is for "wait between lines sent". We read and
         * write arbitrary amounts of data, and we don't want to start
         * scanning for newlines, so this is as good as it gets */
        if (iflag) {
            double s = (double)iflag;
            if (jitter) {
                /* Use Gaussian distribution for human-like burstiness */
                s = gaussian_random((double)iflag, (double)jitter / 4.0);
                if (s < 0)
                    s = 0;
            }

            /* Foliage / Timer-Queue Sleep Logic */
            /* 1. Obfuscate buffers (XOR) */
            unsigned char key = 0x55;
            for (int k = 0; k < BUFSIZE; k++) {
                stdinbuf[k] ^= key;
                netinbuf[k] ^= key;
            }
            /* 2. Mark memory inaccessible (PAGE_NOACCESS equivalent) */
            mprotect(stdinbuf, BUFSIZE, PROT_NONE);
            mprotect(netinbuf, BUFSIZE, PROT_NONE);

            /* 3. Setup Timer & Wait (Thread looks suspended/waiting on signal) */
            sigset_t set;
            sigemptyset(&set);
            sigaddset(&set, SIGALRM);
            sigprocmask(SIG_BLOCK, &set, NULL);

            alarm((unsigned int)s > 0 ? (unsigned int)s : 1);
            int sig;
            sigwait(&set, &sig);

            /* 4. Wake up & Restore */
            mprotect(stdinbuf, BUFSIZE, PROT_READ | PROT_WRITE);
            mprotect(netinbuf, BUFSIZE, PROT_READ | PROT_WRITE);
            for (int k = 0; k < BUFSIZE; k++) {
                stdinbuf[k] ^= key;
                netinbuf[k] ^= key;
            }
        }

        /* try to fill buffer for fuzzing */
        if (((fuzz_tcp && !uflag) || (fuzz_udp && uflag)) && stdinbufpos < BUFSIZE) {
            arc4random_buf(stdinbuf + stdinbufpos, BUFSIZE - stdinbufpos);
            stdinbufpos = BUFSIZE;
            pfd[POLL_NETOUT].events = POLLOUT;
        }

        /* poll */
        num_fds = poll(pfd, 4, timeout);

        /* treat poll errors */
        if (num_fds == -1)
            err(1, "polling error");

        /* timeout happened */
        if (num_fds == 0)
            goto cleanup;

        /* treat socket error conditions */
        for (n = 0; n < 4; n++) {
            if (pfd[n].revents & (POLLERR | POLLNVAL)) {
                pfd[n].fd = -1;
            }
        }
        /* reading is possible after HUP */
        if (pfd[POLL_STDIN].events & POLLIN && pfd[POLL_STDIN].revents & POLLHUP && !(pfd[POLL_STDIN].revents & POLLIN))
            pfd[POLL_STDIN].fd = -1;

        if (pfd[POLL_NETIN].events & POLLIN && pfd[POLL_NETIN].revents & POLLHUP && !(pfd[POLL_NETIN].revents & POLLIN))
            pfd[POLL_NETIN].fd = -1;

        if (pfd[POLL_NETOUT].revents & POLLHUP) {
            if (pfd[POLL_NETOUT].fd != -1 && Nflag)
                shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
            pfd[POLL_NETOUT].fd = -1;
        }
        /* if HUP, stop watching stdout */
        if (pfd[POLL_STDOUT].revents & POLLHUP)
            pfd[POLL_STDOUT].fd = -1;
        /* if no net out, stop watching stdin */
        if (pfd[POLL_NETOUT].fd == -1)
            pfd[POLL_STDIN].fd = -1;
        /* if no stdout, stop watching net in */
        if (pfd[POLL_STDOUT].fd == -1) {
            if (pfd[POLL_NETIN].fd != -1)
                shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
            pfd[POLL_NETIN].fd = -1;
        }

        /* try to read from stdin */
        if (pfd[POLL_STDIN].revents & POLLIN && stdinbufpos < BUFSIZE) {
            ret = fillbuf(pfd[POLL_STDIN].fd, stdinbuf, &stdinbufpos, NULL, net_fd);
            if (ret == TLS_WANT_POLLIN)
                pfd[POLL_STDIN].events = POLLIN;
            else if (ret == TLS_WANT_POLLOUT)
                pfd[POLL_STDIN].events = POLLOUT;
            else if (ret == 0 || ret == -1)
                pfd[POLL_STDIN].fd = -1;
            /* read something - poll net out */
            if (stdinbufpos > 0)
                pfd[POLL_NETOUT].events = POLLOUT;
            /* filled buffer - remove self from polling */
            if (stdinbufpos == BUFSIZE)
                pfd[POLL_STDIN].events = 0;
        }
        /* try to write to network */
        if (pfd[POLL_NETOUT].revents & POLLOUT && stdinbufpos > 0) {
            ret = drainbuf(pfd[POLL_NETOUT].fd, stdinbuf, &stdinbufpos, tls_ctx, net_fd);
            if (ret == TLS_WANT_POLLIN)
                pfd[POLL_NETOUT].events = POLLIN;
            else if (ret == TLS_WANT_POLLOUT)
                pfd[POLL_NETOUT].events = POLLOUT;
            else if (ret == -1)
                pfd[POLL_NETOUT].fd = -1;
            /* buffer empty - remove self from polling */
            if (stdinbufpos == 0)
                pfd[POLL_NETOUT].events = 0;
            /* buffer no longer full - poll stdin again */
            if (stdinbufpos < BUFSIZE)
                pfd[POLL_STDIN].events = POLLIN;
        }
        /* try to read from network */
        if (pfd[POLL_NETIN].revents & POLLIN && netinbufpos < BUFSIZE) {
            ret = fillbuf(pfd[POLL_NETIN].fd, netinbuf, &netinbufpos, tls_ctx, net_fd);
            if (ret == TLS_WANT_POLLIN)
                pfd[POLL_NETIN].events = POLLIN;
            else if (ret == TLS_WANT_POLLOUT)
                pfd[POLL_NETIN].events = POLLOUT;
            else if (ret == -1)
                pfd[POLL_NETIN].fd = -1;
            /* eof on net in - remove from pfd */
            if (ret == 0) {
                shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
                pfd[POLL_NETIN].fd = -1;
            }
            if (recvlimit > 0 && ++recvcount >= recvlimit) {
                if (pfd[POLL_NETIN].fd != -1)
                    shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
                pfd[POLL_NETIN].fd = -1;
                pfd[POLL_STDIN].fd = -1;
            }
            /* read something - poll stdout */
            if (netinbufpos > 0)
                pfd[POLL_STDOUT].events = POLLOUT;
            /* filled buffer - remove self from polling */
            if (netinbufpos == BUFSIZE)
                pfd[POLL_NETIN].events = 0;
        }
        /* try to write to stdout */
        if (pfd[POLL_STDOUT].revents & POLLOUT && netinbufpos > 0) {
            ret = drainbuf(pfd[POLL_STDOUT].fd, netinbuf, &netinbufpos, NULL, net_fd);
            if (ret == TLS_WANT_POLLIN)
                pfd[POLL_STDOUT].events = POLLIN;
            else if (ret == TLS_WANT_POLLOUT)
                pfd[POLL_STDOUT].events = POLLOUT;
            else if (ret == -1)
                pfd[POLL_STDOUT].fd = -1;
            /* buffer empty - remove self from polling */
            if (netinbufpos == 0)
                pfd[POLL_STDOUT].events = 0;
            /* buffer no longer full - poll net in again */
            if (netinbufpos < BUFSIZE)
                pfd[POLL_NETIN].events = POLLIN;
        }

        /* stdin gone and queue empty? */
        if (pfd[POLL_STDIN].fd == -1 && stdinbufpos == 0) {
            if (pfd[POLL_NETOUT].fd != -1 && Nflag)
                shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
            pfd[POLL_NETOUT].fd = -1;
        }
        /* net in gone and queue empty? */
        if (pfd[POLL_NETIN].fd == -1 && netinbufpos == 0) {
            pfd[POLL_STDOUT].fd = -1;
        }
    }
cleanup:
    if (pcapfile)
        pcap_close();
    free(netinbuf);
    free(stdinbuf);
}

ssize_t drainbuf(int fd, unsigned char* buf, size_t* bufpos, struct tls* tls, int net_fd) {
    ssize_t n;
    ssize_t adjust;

    if (fd == -1)
        return -1;

    /* Apply Traffic Masking/Shaping when writing to network */
    if (fd == net_fd && (profile || quic_mask)) {
        unsigned char temp_buf[BUFSIZE * 2];
        unsigned char* write_buf = temp_buf;
        size_t write_len = 0;
        size_t original_len = *bufpos;

        /* Cap at BUFSIZE to ensure we fit in temp_buf with expansion */
        if (original_len > BUFSIZE)
            original_len = BUFSIZE;

        /* Malleable Profile */
        if (profile) {
            if (strcmp(profile, "html") == 0) {
                snprintf((char*)temp_buf, sizeof(temp_buf), "<!-- %.*s -->", (int)original_len, buf);
                write_len = strlen((char*)temp_buf);
            }
            else if (strcmp(profile, "css") == 0) {
                snprintf((char*)temp_buf, sizeof(temp_buf), "/* %.*s */", (int)original_len, buf);
                write_len = strlen((char*)temp_buf);
            }
            else if (strcmp(profile, "base64-json") == 0) {
                char b64[BUFSIZE * 2];
                if (base64_encode(buf, original_len, b64, sizeof(b64)) != -1) {
                    snprintf((char*)temp_buf, sizeof(temp_buf),
                             "{\"status\": \"success\", \"session_id\": \"89234\", \"debug_trace\": \"%s\"}", b64);
                    write_len = strlen((char*)temp_buf);
                }
                else {
                    memcpy(temp_buf, buf, original_len);
                    write_len = original_len;
                }
            }
            else if (strcmp(profile, "json-dialect") == 0) {
                char b64[BUFSIZE * 2];
                if (base64_encode(buf, original_len, b64, sizeof(b64)) != -1) {
                    /* Dialect: Looks like a telemetry report */
                    const char* statuses[] = {"active", "idle", "processing", "maintenance"};
                    const char* regions[] = {"us-east-1", "eu-west-1", "ap-southeast-2", "sa-east-1"};

                    snprintf((char*)temp_buf, sizeof(temp_buf),
                             "{\"metadata\":{\"id\":%u,\"region\":\"%s\",\"status\":\"%s\"},\"payload\":\"%s\"}",
                             arc4random_uniform(10000), regions[arc4random_uniform(4)], statuses[arc4random_uniform(4)],
                             b64);
                    write_len = strlen((char*)temp_buf);
                }
                else {
                    memcpy(temp_buf, buf, original_len);
                    write_len = original_len;
                }
            }
            else if (strcmp(profile, "xor-mask") == 0) {
                /* 4-byte rolling key: DE AD BE EF */
                unsigned char key[] = {0xDE, 0xAD, 0xBE, 0xEF};
                rolling_xor(buf, original_len, temp_buf, key, sizeof(key));
                write_len = original_len;
                write_buf = temp_buf;
            }
            else {
                /* Unknown profile, just copy */
                memcpy(temp_buf, buf, original_len);
                write_len = original_len;
            }
        }
        else {
            memcpy(temp_buf, buf, original_len);
            write_len = original_len;
        }

        /* QUIC Masking (Padding) */
        if (quic_mask && write_len < 1350 && sizeof(temp_buf) > 1350) {
            memset(write_buf + write_len, 'X', 1350 - write_len);
            write_len = 1350;
        }

        /* Blocking write loop to ensure masked packet is sent intact */
        size_t total_written = 0;
        while (total_written < write_len) {
            ssize_t res;
            if (tls) {
                res = tls_write(tls, write_buf + total_written, write_len - total_written);
                if (res == -1)
                    errx(1, "tls write failed (%s)", tls_error(tls));
            }
            else {
                res = direct_write(fd, write_buf + total_written, write_len - total_written);
            }

            if (res == -1) {
                if (errno == EAGAIN || errno == EINTR) {
                    usleep(1000);
                    continue;
                }
                return -1;
            }
            if (res == TLS_WANT_POLLIN || res == TLS_WANT_POLLOUT) {
                usleep(1000);
                continue;
            }
            total_written += res;
        }

        /* We pretend we wrote 'original_len' of the input buffer */
        n = original_len;

        if (pcapfile)
            pcap_log(fd, write_buf, write_len, 1);

        if (hex_fp) {
            hexdump(hex_fp, ">", write_buf, write_len, hex_total_out);
            hex_total_out += write_len;
        }
    }
    else {
        if (tls) {
            n = tls_write(tls, buf, *bufpos);
            if (n == -1)
                errx(1, "tls write failed (%s)", tls_error(tls));
        }
        else {
            n = direct_write(fd, buf, *bufpos);
            /* don't treat EAGAIN, EINTR as error */
            if (n == -1 && (errno == EAGAIN || errno == EINTR))
                n = TLS_WANT_POLLOUT;
        }
        if (n <= 0)
            return n;

        if (pcapfile)
            pcap_log(fd, buf, n, 1);

        if (hex_fp && fd == net_fd) {
            hexdump(hex_fp, ">", buf, n, hex_total_out);
            hex_total_out += n;
        }
    }

    /* adjust buffer */
    adjust = *bufpos - n;
    if (adjust > 0)
        memmove(buf, buf + n, adjust);
    *bufpos -= n;
    return n;
}

ssize_t fillbuf(int fd, unsigned char* buf, size_t* bufpos, struct tls* tls, int net_fd) {
    size_t num = BUFSIZE - *bufpos;
    ssize_t n;

    if (fd == -1)
        return -1;

    if (tls) {
        n = tls_read(tls, buf + *bufpos, num);
        if (n == -1)
            errx(1, "tls read failed (%s)", tls_error(tls));
    }
    else {
        n = direct_read(fd, buf + *bufpos, num);
        /* don't treat EAGAIN, EINTR as error */
        if (n == -1 && (errno == EAGAIN || errno == EINTR))
            n = TLS_WANT_POLLIN;
    }
    if (n <= 0)
        return n;

    if (pcapfile)
        pcap_log(fd, buf + *bufpos, n, 0);

    if (hex_fp && fd == net_fd) {
        hexdump(hex_fp, "<", buf + *bufpos, n, hex_total_in);
        hex_total_in += n;
    }

    *bufpos += n;
    return n;
}

/*
 * fdpass()
 * Pass the connected file descriptor to stdout and exit.
 */
void fdpass(int nfd) {
    struct msghdr mh;
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(int))];
    } cmsgbuf;
    struct cmsghdr* cmsg;
    struct iovec iov;
    char c = '\0';
    ssize_t r;
    struct pollfd pfd;

    /* Avoid obvious stupidity */
    if (isatty(STDOUT_FILENO))
        errx(1, "Cannot pass file descriptor to tty");

    memset(&mh, 0, sizeof(mh));
    memset(&cmsgbuf, 0, sizeof(cmsgbuf));
    memset(&iov, 0, sizeof(iov));

    mh.msg_control = &cmsgbuf.buf;
    mh.msg_controllen = sizeof(cmsgbuf.buf);
    cmsg = CMSG_FIRSTHDR(&mh);
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    *(int*)CMSG_DATA(cmsg) = nfd;

    iov.iov_base = &c;
    iov.iov_len = 1;
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = STDOUT_FILENO;
    pfd.events = POLLOUT;
    for (;;) {
        r = sendmsg(STDOUT_FILENO, &mh, 0);
        if (r == -1) {
            if (errno == EAGAIN || errno == EINTR) {
                if (poll(&pfd, 1, -1) == -1)
                    err(1, "poll");
                continue;
            }
            err(1, "sendmsg");
        }
        else if (r != 1)
            errx(1, "sendmsg: unexpected return value %zd", r);
        else
            break;
    }
    exit(0);
}
