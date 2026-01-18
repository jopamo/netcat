/*
 * Direct System Call wrappers to bypass user-land hooks (EDR evasion).
 *
 * Implements direct assembly syscalls for critical functions like write() and connect().
 * Only active on Linux x86_64. Falls back to libc on other platforms.
 */

#ifndef _SYSCALLS_H
#define _SYSCALLS_H

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>

#if defined(__linux__) && defined(__x86_64__)

/*
 * direct_write - implementation of write() using inline assembly.
 * syscall number for write is 1 on x86_64.
 * Arguments:
 *   rax: 1 (syscall number)
 *   rdi: fd
 *   rsi: buf
 *   rdx: count
 */
static inline ssize_t direct_write(int fd, const void* buf, size_t count) {
    ssize_t ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(__NR_write), "D"(fd), "S"(buf), "d"(count) : "rcx", "r11", "memory");
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

/*
 * direct_read - implementation of read() using inline assembly.
 * syscall number for read is 0 on x86_64.
 * Arguments:
 *   rax: 0 (syscall number)
 *   rdi: fd
 *   rsi: buf
 *   rdx: count
 */
static inline ssize_t direct_read(int fd, void* buf, size_t count) {
    ssize_t ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(__NR_read), "D"(fd), "S"(buf), "d"(count) : "rcx", "r11", "memory");
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

/*
 * direct_socket - implementation of socket() using inline assembly.
 * syscall number for socket is 41 on x86_64.
 * Arguments:
 *   rax: 41 (syscall number)
 *   rdi: domain
 *   rsi: type
 *   rdx: protocol
 */
static inline int direct_socket(int domain, int type, int protocol) {
    int ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(__NR_socket), "D"(domain), "S"(type), "d"(protocol)
                     : "rcx", "r11", "memory");
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

/*
 * direct_bind - implementation of bind() using inline assembly.
 * syscall number for bind is 49 on x86_64.
 * Arguments:
 *   rax: 49 (syscall number)
 *   rdi: sockfd
 *   rsi: addr
 *   rdx: addrlen
 */
static inline int direct_bind(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    int ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(__NR_bind), "D"(sockfd), "S"(addr), "d"(addrlen)
                     : "rcx", "r11", "memory");
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

/*
 * direct_listen - implementation of listen() using inline assembly.
 * syscall number for listen is 50 on x86_64.
 * Arguments:
 *   rax: 50 (syscall number)
 *   rdi: sockfd
 *   rsi: backlog
 */
static inline int direct_listen(int sockfd, int backlog) {
    int ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(__NR_listen), "D"(sockfd), "S"(backlog) : "rcx", "r11", "memory");
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

/*
 * direct_connect - implementation of connect() using inline assembly.
 * syscall number for connect is 42 on x86_64.
 * Arguments:
 *   rax: 42 (syscall number)
 *   rdi: sockfd
 *   rsi: addr
 *   rdx: addrlen
 */
static inline int direct_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    int ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(__NR_connect), "D"(sockfd), "S"(addr), "d"(addrlen)
                     : "rcx", "r11", "memory");
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

#elif defined(__linux__) && defined(__aarch64__)

/*
 * direct_write - implementation of write() using inline assembly for ARM64.
 * Arguments:
 *   x8: syscall number
 *   x0: fd
 *   x1: buf
 *   x2: count
 */
static inline ssize_t direct_write(int fd, const void* buf, size_t count) {
    register long x8 asm("x8") = __NR_write;
    register long x0 asm("x0") = (long)fd;
    register long x1 asm("x1") = (long)buf;
    register long x2 asm("x2") = (long)count;

    __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8), "0"(x0), "r"(x1), "r"(x2) : "memory", "cc");

    if (x0 < 0) {
        errno = -x0;
        return -1;
    }
    return x0;
}

/*
 * direct_read - implementation of read() using inline assembly for ARM64.
 * Arguments:
 *   x8: syscall number
 *   x0: fd
 *   x1: buf
 *   x2: count
 */
static inline ssize_t direct_read(int fd, void* buf, size_t count) {
    register long x8 asm("x8") = __NR_read;
    register long x0 asm("x0") = (long)fd;
    register long x1 asm("x1") = (long)buf;
    register long x2 asm("x2") = (long)count;

    __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8), "0"(x0), "r"(x1), "r"(x2) : "memory", "cc");

    if (x0 < 0) {
        errno = -x0;
        return -1;
    }
    return x0;
}

/*
 * direct_socket - implementation of socket() using inline assembly for ARM64.
 * Arguments:
 *   x8: syscall number
 *   x0: domain
 *   x1: type
 *   x2: protocol
 */
static inline int direct_socket(int domain, int type, int protocol) {
    register long x8 asm("x8") = __NR_socket;
    register long x0 asm("x0") = (long)domain;
    register long x1 asm("x1") = (long)type;
    register long x2 asm("x2") = (long)protocol;

    __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8), "0"(x0), "r"(x1), "r"(x2) : "memory", "cc");

    if (x0 < 0) {
        errno = -x0;
        return -1;
    }
    return x0;
}

/*
 * direct_bind - implementation of bind() using inline assembly for ARM64.
 * Arguments:
 *   x8: syscall number
 *   x0: sockfd
 *   x1: addr
 *   x2: addrlen
 */
static inline int direct_bind(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    register long x8 asm("x8") = __NR_bind;
    register long x0 asm("x0") = (long)sockfd;
    register long x1 asm("x1") = (long)addr;
    register long x2 asm("x2") = (long)addrlen;

    __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8), "0"(x0), "r"(x1), "r"(x2) : "memory", "cc");

    if (x0 < 0) {
        errno = -x0;
        return -1;
    }
    return x0;
}

/*
 * direct_listen - implementation of listen() using inline assembly for ARM64.
 * Arguments:
 *   x8: syscall number
 *   x0: sockfd
 *   x1: backlog
 */
static inline int direct_listen(int sockfd, int backlog) {
    register long x8 asm("x8") = __NR_listen;
    register long x0 asm("x0") = (long)sockfd;
    register long x1 asm("x1") = (long)backlog;

    __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8), "0"(x0), "r"(x1) : "memory", "cc");

    if (x0 < 0) {
        errno = -x0;
        return -1;
    }
    return x0;
}

/*
 * direct_connect - implementation of connect() using inline assembly for ARM64.
 * Arguments:
 *   x8: syscall number
 *   x0: sockfd
 *   x1: addr
 *   x2: addrlen
 */
static inline int direct_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    register long x8 asm("x8") = __NR_connect;
    register long x0 asm("x0") = (long)sockfd;
    register long x1 asm("x1") = (long)addr;
    register long x2 asm("x2") = (long)addrlen;

    __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8), "0"(x0), "r"(x1), "r"(x2) : "memory", "cc");

    if (x0 < 0) {
        errno = -x0;
        return -1;
    }
    return x0;
}

#else

#error "Direct system calls not implemented for this architecture. Only Linux x86_64 and ARM64 are supported."

#endif

#endif /* _SYSCALLS_H */
