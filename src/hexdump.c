#include <unistd.h>
#include <stdio.h>
#include <stdint.h>

void nc_hexdump_write(int fd, const unsigned char* buf, size_t len, uint64_t base) {
    char line[128];
    for (size_t off = 0; off < len; off += 16) {
        size_t n = len - off;
        if (n > 16)
            n = 16;

        int p = snprintf(line, sizeof(line), "%08llx  ", (unsigned long long)(base + off));
        for (size_t i = 0; i < 16; i++) {
            if (i < n)
                p += snprintf(line + p, sizeof(line) - p, "%02x ", buf[off + i]);
            else
                p += snprintf(line + p, sizeof(line) - p, "   ");
        }
        p += snprintf(line + p, sizeof(line) - p, " |");
        for (size_t i = 0; i < n; i++) {
            unsigned char c = buf[off + i];
            line[p++] = (c >= 32 && c < 127) ? (char)c : '.';
        }
        line[p++] = '|';
        line[p++] = '\n';
        (void)write(fd, line, (size_t)p);
    }
}