#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include "atomicio.h"

static int call_count = 0;

static ssize_t mock_read_short(int fd, void* buf, size_t n) {
    call_count++;
    if (call_count == 1)
        return 1;
    if (call_count == 2)
        return 2;
    return n;
}

static ssize_t mock_read_eintr(int fd, void* buf, size_t n) {
    call_count++;
    if (call_count == 1) {
        errno = EINTR;
        return -1;
    }
    return n;
}

static ssize_t mock_read_eof(int fd, void* buf, size_t n) {
    call_count++;
    return 0;
}

static void test_short_io() {
    char buf[10];
    size_t ret;

    call_count = 0;
    ret = atomicio(mock_read_short, -1, buf, 5);
    assert(ret == 5);
    assert(call_count == 3);
    printf("test_short_io passed\n");
}

static void test_eintr() {
    char buf[10];
    size_t ret;

    call_count = 0;
    ret = atomicio(mock_read_eintr, -1, buf, 5);
    assert(ret == 5);
    assert(call_count == 2);
    printf("test_eintr passed\n");
}

static void test_eof() {
    char buf[10];
    size_t ret;

    call_count = 0;
    errno = 0;
    ret = atomicio(mock_read_eof, -1, buf, 5);
    assert(ret == 0);
    assert(errno == EPIPE);
    assert(call_count == 1);
    printf("test_eof passed\n");
}

int main() {
    test_short_io();
    test_eintr();
    test_eof();
    return 0;
}
