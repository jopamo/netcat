/*
 * Indirect System Call wrappers to bypass user-land hooks (EDR evasion).
 *
 * Implements indirect assembly syscalls (trampoline) for critical functions.
 * Finds a 'syscall' or 'svc #0' instruction in existing executable memory (e.g. read/libc)
 * and jumps to it, avoiding direct usage of the instruction in our code.
 * Only active on Linux x86_64 and ARM64.
 */

#ifndef _SYSCALLS_H
#define _SYSCALLS_H

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>

static void* syscall_gadget = NULL;

static void find_gadget(void) {
    if (syscall_gadget)
        return;
    /* Scan 'read' function for syscall instruction */
    unsigned char* p = (unsigned char*)read;
    for (int i = 0; i < 500; i++) {
#if defined(__x86_64__)
        /* 0f 05 = syscall */
        if (p[i] == 0x0f && p[i + 1] == 0x05) {
            syscall_gadget = (void*)(p + i);
            break;
        }
#elif defined(__aarch64__)
        /* 01 00 00 d4 = svc #0 (Little Endian) */
        if (p[i] == 0x01 && p[i + 1] == 0x00 && p[i + 2] == 0x00 && p[i + 3] == 0xd4) {
            syscall_gadget = (void*)(p + i);
            break;
        }
#endif
    }
}

#if defined(__linux__) && defined(__x86_64__)

static inline ssize_t direct_write(int fd, const void* buf, size_t count) {
    if (!syscall_gadget)
        find_gadget();
    ssize_t ret;
    if (syscall_gadget) {
        __asm__ volatile("call *%5"
                         : "=a"(ret)
                         : "a"(__NR_write), "D"(fd), "S"(buf), "d"(count), "r"(syscall_gadget)
                         : "rcx", "r11", "memory");
    }
    else {
        __asm__ volatile("syscall"
                         : "=a"(ret)
                         : "a"(__NR_write), "D"(fd), "S"(buf), "d"(count)
                         : "rcx", "r11", "memory");
    }
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

static inline ssize_t direct_read(int fd, void* buf, size_t count) {
    if (!syscall_gadget)
        find_gadget();
    ssize_t ret;
    if (syscall_gadget) {
        __asm__ volatile("call *%5"
                         : "=a"(ret)
                         : "a"(__NR_read), "D"(fd), "S"(buf), "d"(count), "r"(syscall_gadget)
                         : "rcx", "r11", "memory");
    }
    else {
        __asm__ volatile("syscall"
                         : "=a"(ret)
                         : "a"(__NR_read), "D"(fd), "S"(buf), "d"(count)
                         : "rcx", "r11", "memory");
    }
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

static inline int direct_socket(int domain, int type, int protocol) {
    if (!syscall_gadget)
        find_gadget();
    int ret;
    if (syscall_gadget) {
        __asm__ volatile("call *%5"
                         : "=a"(ret)
                         : "a"(__NR_socket), "D"(domain), "S"(type), "d"(protocol), "r"(syscall_gadget)
                         : "rcx", "r11", "memory");
    }
    else {
        __asm__ volatile("syscall"
                         : "=a"(ret)
                         : "a"(__NR_socket), "D"(domain), "S"(type), "d"(protocol)
                         : "rcx", "r11", "memory");
    }
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

static inline int direct_bind(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    if (!syscall_gadget)
        find_gadget();
    int ret;
    if (syscall_gadget) {
        __asm__ volatile("call *%5"
                         : "=a"(ret)
                         : "a"(__NR_bind), "D"(sockfd), "S"(addr), "d"(addrlen), "r"(syscall_gadget)
                         : "rcx", "r11", "memory");
    }
    else {
        __asm__ volatile("syscall"
                         : "=a"(ret)
                         : "a"(__NR_bind), "D"(sockfd), "S"(addr), "d"(addrlen)
                         : "rcx", "r11", "memory");
    }
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

static inline int direct_listen(int sockfd, int backlog) {
    if (!syscall_gadget)
        find_gadget();
    int ret;
    if (syscall_gadget) {
        __asm__ volatile("call *%4"
                         : "=a"(ret)
                         : "a"(__NR_listen), "D"(sockfd), "S"(backlog), "r"(syscall_gadget)
                         : "rcx", "r11", "memory");
    }
    else {
        __asm__ volatile("syscall" : "=a"(ret) : "a"(__NR_listen), "D"(sockfd), "S"(backlog) : "rcx", "r11", "memory");
    }
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

static inline int direct_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    if (!syscall_gadget)
        find_gadget();
    int ret;
    if (syscall_gadget) {
        __asm__ volatile("call *%5"
                         : "=a"(ret)
                         : "a"(__NR_connect), "D"(sockfd), "S"(addr), "d"(addrlen), "r"(syscall_gadget)
                         : "rcx", "r11", "memory");
    }
    else {
        __asm__ volatile("syscall"
                         : "=a"(ret)
                         : "a"(__NR_connect), "D"(sockfd), "S"(addr), "d"(addrlen)
                         : "rcx", "r11", "memory");
    }
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

#elif defined(__linux__) && defined(__aarch64__)

static inline ssize_t direct_write(int fd, const void* buf, size_t count) {
    if (!syscall_gadget)
        find_gadget();
    register long x8 asm("x8") = __NR_write;
    register long x0 asm("x0") = (long)fd;
    register long x1 asm("x1") = (long)buf;
    register long x2 asm("x2") = (long)count;

    if (syscall_gadget) {
        register void* gadget asm("x9") = syscall_gadget;
        __asm__ volatile("blr %5" : "=r"(x0) : "r"(x8), "0"(x0), "r"(x1), "r"(x2), "r"(gadget) : "memory", "cc", "x30");
    }
    else {
        __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8), "0"(x0), "r"(x1), "r"(x2) : "memory", "cc");
    }

    if (x0 < 0) {
        errno = -x0;
        return -1;
    }
    return x0;
}

static inline ssize_t direct_read(int fd, void* buf, size_t count) {
    if (!syscall_gadget)
        find_gadget();
    register long x8 asm("x8") = __NR_read;
    register long x0 asm("x0") = (long)fd;
    register long x1 asm("x1") = (long)buf;
    register long x2 asm("x2") = (long)count;

    if (syscall_gadget) {
        register void* gadget asm("x9") = syscall_gadget;
        __asm__ volatile("blr %5" : "=r"(x0) : "r"(x8), "0"(x0), "r"(x1), "r"(x2), "r"(gadget) : "memory", "cc", "x30");
    }
    else {
        __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8), "0"(x0), "r"(x1), "r"(x2) : "memory", "cc");
    }

    if (x0 < 0) {
        errno = -x0;
        return -1;
    }
    return x0;
}

static inline int direct_socket(int domain, int type, int protocol) {
    if (!syscall_gadget)
        find_gadget();
    register long x8 asm("x8") = __NR_socket;
    register long x0 asm("x0") = (long)domain;
    register long x1 asm("x1") = (long)type;
    register long x2 asm("x2") = (long)protocol;

    if (syscall_gadget) {
        register void* gadget asm("x9") = syscall_gadget;
        __asm__ volatile("blr %5" : "=r"(x0) : "r"(x8), "0"(x0), "r"(x1), "r"(x2), "r"(gadget) : "memory", "cc", "x30");
    }
    else {
        __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8), "0"(x0), "r"(x1), "r"(x2) : "memory", "cc");
    }

    if (x0 < 0) {
        errno = -x0;
        return -1;
    }
    return x0;
}

static inline int direct_bind(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    if (!syscall_gadget)
        find_gadget();
    register long x8 asm("x8") = __NR_bind;
    register long x0 asm("x0") = (long)sockfd;
    register long x1 asm("x1") = (long)addr;
    register long x2 asm("x2") = (long)addrlen;

    if (syscall_gadget) {
        register void* gadget asm("x9") = syscall_gadget;
        __asm__ volatile("blr %5" : "=r"(x0) : "r"(x8), "0"(x0), "r"(x1), "r"(x2), "r"(gadget) : "memory", "cc", "x30");
    }
    else {
        __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8), "0"(x0), "r"(x1), "r"(x2) : "memory", "cc");
    }

    if (x0 < 0) {
        errno = -x0;
        return -1;
    }
    return x0;
}

static inline int direct_listen(int sockfd, int backlog) {
    if (!syscall_gadget)
        find_gadget();
    register long x8 asm("x8") = __NR_listen;
    register long x0 asm("x0") = (long)sockfd;
    register long x1 asm("x1") = (long)backlog;

    if (syscall_gadget) {
        register void* gadget asm("x9") = syscall_gadget;
        __asm__ volatile("blr %4" : "=r"(x0) : "r"(x8), "0"(x0), "r"(x1), "r"(gadget) : "memory", "cc", "x30");
    }
    else {
        __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8), "0"(x0), "r"(x1) : "memory", "cc");
    }

    if (x0 < 0) {
        errno = -x0;
        return -1;
    }
    return x0;
}

static inline int direct_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    if (!syscall_gadget)
        find_gadget();
    register long x8 asm("x8") = __NR_connect;
    register long x0 asm("x0") = (long)sockfd;
    register long x1 asm("x1") = (long)addr;
    register long x2 asm("x2") = (long)addrlen;

    if (syscall_gadget) {
        register void* gadget asm("x9") = syscall_gadget;
        __asm__ volatile("blr %5" : "=r"(x0) : "r"(x8), "0"(x0), "r"(x1), "r"(x2), "r"(gadget) : "memory", "cc", "x30");
    }
    else {
        __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8), "0"(x0), "r"(x1), "r"(x2) : "memory", "cc");
    }

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