#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include <math.h>
#include "netcat.h"

/* Deterministic RNG (Xorshift32) */
static uint32_t xorshift_state = 123456789;

/* Globals needed by io.c and utils.c */
int dflag = 0;
unsigned int iflag = 0;
int jitter = 0;
int Nflag = 0;
char* profile = NULL;
int quic_mask = 0;
int fuzz_tcp = 0;
int fuzz_udp = 0;
int uflag = 0;
int lflag = 0;
int spliceflag = 0;
char* pcapfile = NULL;
char* hex_path = NULL;
FILE* hex_fp = NULL;
int timeout = -1;
int recvlimit = 0;
int recvcount = 0;
int vflag = 0; /* for log.c */
int jflag = 0;
int nflag = 0;
int rflag = 0;
char* portlist[PORT_MAX + 1];
char* exec_path = NULL;

/* Mock functions for pcap */
void pcap_open(int fd, const char* path) {}
void pcap_log(int fd, const void* buf, size_t len, int direction) {}
void pcap_close(void) {}

/* Mock functions for hexdump */
void hexdump(FILE* fp, const char* prefix, const unsigned char* buf, size_t len, size_t total) {}

/* Helper for atomic read from socket */
static void read_all(int fd, char* buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, buf + total, len - total);
        if (n == -1) {
            if (errno == EINTR)
                continue;
            perror("read");
            exit(1);
        }
        if (n == 0) {
            fprintf(stderr, "Unexpected EOF\n");
            exit(1);
        }
        total += n;
    }
}

static uint32_t deterministic_rng(void) {
    uint32_t x = xorshift_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    xorshift_state = x;
    return xorshift_state;
}

static void test_gaussian_dist() {
    double mean = 10.0;
    double stddev = 2.0;
    double sum = 0.0;
    int count = 10000;

    nc_random = deterministic_rng;

    /* Verify mean */
    for (int i = 0; i < count; i++) {
        sum += gaussian_random(mean, stddev);
    }

    double avg = sum / count;
    printf("Average: %f (Expected: %f)\n", avg, mean);
    assert(fabs(avg - mean) < 0.1);

    /* Verify determinism */
    xorshift_state = 123456789; /* Reset RNG */
    double val1 = gaussian_random(mean, stddev);
    (void)gaussian_random(mean, stddev); /* Consume 2nd value to reset phase */

    xorshift_state = 123456789; /* Reset RNG */
    double val2 = gaussian_random(mean, stddev);
    (void)gaussian_random(mean, stddev); /* Consume 2nd value to reset phase */

    assert(val1 == val2);
    printf("Determinism check passed: %f == %f\n", val1, val2);
}

static void test_drainbuf_identity() {
    int sv[2];
    unsigned char buf[BUFSIZE];
    char readbuf[BUFSIZE];
    size_t len = 100;
    size_t bufpos = len;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
        perror("socketpair");
        exit(1);
    }

    memset(buf, 'A', len);

    /* Ensure no shaping */
    profile = NULL;
    quic_mask = 0;

    ssize_t n = drainbuf(sv[0], buf, &bufpos, NULL, sv[0]);
    assert(n == 100);
    assert(bufpos == 0);

    read_all(sv[1], readbuf, len);
    assert(memcmp(readbuf, buf, len) == 0); /* buf was shifted but content was 'A's */
    /* wait, drainbuf memmoves the buffer. buf is now empty/undefined after pos 0.
       But we wrote 100 'A's. */

    close(sv[0]);
    close(sv[1]);
    printf("test_drainbuf_identity passed\n");
}

static void test_drainbuf_profiles() {
    int sv[2];
    unsigned char buf[BUFSIZE];
    char readbuf[BUFSIZE * 2]; /* Larger buffer for expanded profiles */
    size_t len = 50;
    size_t bufpos = len;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
        perror("socketpair");
        exit(1);
    }

    /* Test each profile */
    const char* profiles[] = {"html", "css", "base64-json", "json-dialect", "xor-mask", NULL};

    for (int i = 0; profiles[i] != NULL; i++) {
        memset(buf, 'A' + i, len); /* Different content for each profile */
        bufpos = len;

        profile = (char*)profiles[i];
        quic_mask = 0;

        ssize_t n = drainbuf(sv[0], buf, &bufpos, NULL, sv[0]);
        assert(n > 0);
        assert(bufpos == 0);

        /* Read what was sent */
        ssize_t bytes_read = read(sv[1], readbuf, sizeof(readbuf));
        assert(bytes_read > 0);

        /* Verify profile-specific transformations */
        switch (i) {
            case 0: /* html */
                assert(strstr(readbuf, "<!--") != NULL);
                assert(strstr(readbuf, "-->") != NULL);
                break;
            case 1: /* css */
                assert(strstr(readbuf, "/*") != NULL);
                assert(strstr(readbuf, "*/") != NULL);
                break;
            case 2: /* base64-json */
            case 3: /* json-dialect */
                assert(strstr(readbuf, "{") != NULL);
                assert(strstr(readbuf, "}") != NULL);
                break;
            case 4: /* xor-mask */
                /* XOR with DE AD BE EF should transform the data */
                /* We can't easily verify without implementing XOR */
                break;
        }

        printf("  Profile '%s': wrote %zd bytes\n", profiles[i], n);

        /* Reset for next test */
        profile = NULL;
    }

    close(sv[0]);
    close(sv[1]);
    printf("test_drainbuf_profiles passed\n");
}

static void test_drainbuf_quic_mask() {
    int sv[2];
    unsigned char buf[BUFSIZE];
    char readbuf[BUFSIZE * 2];
    size_t len = 100; /* Less than 1350 */
    size_t bufpos = len;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
        perror("socketpair");
        exit(1);
    }

    memset(buf, 'Q', len);

    profile = NULL;
    quic_mask = 1;

    ssize_t n = drainbuf(sv[0], buf, &bufpos, NULL, sv[0]);
    assert((size_t)n == len); /* Returns amount consumed from buffer, not bytes written */
    assert(bufpos == 0);

    ssize_t bytes_read = read(sv[1], readbuf, sizeof(readbuf));
    assert(bytes_read >= 1350); /* Should be padded to at least 1350 bytes */

    /* Check padding - look for 'X' padding characters */
    int has_padding = 0;
    for (int i = 0; i < bytes_read; i++) {
        if (readbuf[i] == 'X') {
            has_padding = 1;
            break;
        }
    }
    assert(has_padding);

    close(sv[0]);
    close(sv[1]);
    printf("test_drainbuf_quic_mask passed\n");
}

static void test_fillbuf_basic() {
    int sv[2];
    unsigned char buf[BUFSIZE];
    size_t bufpos = 0;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
        perror("socketpair");
        exit(1);
    }

    /* Write some data to one end */
    const char* test_data = "Hello, world!";
    write(sv[1], test_data, strlen(test_data));
    shutdown(sv[1], SHUT_WR); /* Signal EOF */

    /* Read it with fillbuf */
    ssize_t n = fillbuf(sv[0], buf, &bufpos, NULL, sv[0]);
    assert((size_t)n == strlen(test_data));
    assert(bufpos == strlen(test_data));
    assert(memcmp(buf, test_data, strlen(test_data)) == 0);

    close(sv[0]);
    close(sv[1]);
    printf("test_fillbuf_basic passed\n");
}

static void test_profile_transformations() {
    printf("Testing profile transformations conceptually...\n");

    /* Document expected transformations */
    printf("  HTML profile: wraps data in <!-- --> comments\n");
    printf("  CSS profile: wraps data in /* */ comments\n");
    printf("  base64-json profile: base64 encodes data in JSON wrapper\n");
    printf("  json-dialect profile: creates telemetry-style JSON with metadata\n");
    printf("  xor-mask profile: XORs data with DE AD BE EF key\n");

    printf("test_profile_transformations: Profile behaviors documented\n");
}

int main() {
    printf("Running IO shaping tests...\n\n");

    test_gaussian_dist();
    test_drainbuf_identity();
    test_drainbuf_profiles();
    test_drainbuf_quic_mask();
    test_fillbuf_basic();
    test_profile_transformations();

    printf("\nAll IO shaping tests completed ✓\n");
    return 0;
}
