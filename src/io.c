#include "netcat.h"
#include <fcntl.h>

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
    unsigned char netinbuf[BUFSIZE];
    size_t netinbufpos = 0;
    unsigned char stdinbuf[BUFSIZE];
    size_t stdinbufpos = 0;
    int n, num_fds;
    ssize_t ret;

    if (spliceflag && !tls_ctx) {
        splice_loop(net_fd);
        return;
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
            return;
        /* both outputs are gone, we can't continue */
        if (pfd[POLL_NETOUT].fd == -1 && pfd[POLL_STDOUT].fd == -1)
            return;
        /* listen and net in gone, queues empty, done */
        if (lflag && pfd[POLL_NETIN].fd == -1 && stdinbufpos == 0 && netinbufpos == 0)
            return;

        /* help says -i is for "wait between lines sent". We read and
         * write arbitrary amounts of data, and we don't want to start
         * scanning for newlines, so this is as good as it gets */
        if (iflag)
            sleep(iflag);

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
            return;

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
            ret = fillbuf(pfd[POLL_STDIN].fd, stdinbuf, &stdinbufpos, NULL);
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
            ret = drainbuf(pfd[POLL_NETOUT].fd, stdinbuf, &stdinbufpos, tls_ctx);
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
            ret = fillbuf(pfd[POLL_NETIN].fd, netinbuf, &netinbufpos, tls_ctx);
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
            ret = drainbuf(pfd[POLL_STDOUT].fd, netinbuf, &netinbufpos, NULL);
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
}

ssize_t drainbuf(int fd, unsigned char* buf, size_t* bufpos, struct tls* tls) {
    ssize_t n;
    ssize_t adjust;

    if (fd == -1)
        return -1;

    if (tls) {
        n = tls_write(tls, buf, *bufpos);
        if (n == -1)
            errx(1, "tls write failed (%s)", tls_error(tls));
    }
    else {
        n = write(fd, buf, *bufpos);
        /* don't treat EAGAIN, EINTR as error */
        if (n == -1 && (errno == EAGAIN || errno == EINTR))
            n = TLS_WANT_POLLOUT;
    }
    if (n <= 0)
        return n;
    /* adjust buffer */
    adjust = *bufpos - n;
    if (adjust > 0)
        memmove(buf, buf + n, adjust);
    *bufpos -= n;
    return n;
}

ssize_t fillbuf(int fd, unsigned char* buf, size_t* bufpos, struct tls* tls) {
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
        n = read(fd, buf + *bufpos, num);
        /* don't treat EAGAIN, EINTR as error */
        if (n == -1 && (errno == EAGAIN || errno == EINTR))
            n = TLS_WANT_POLLIN;
    }
    if (n <= 0)
        return n;
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
