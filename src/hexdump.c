#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include "nc_ctx.h"

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

// direction: 0 = sent to network (>), 1 = received (<)
void nc_hexdump_log(struct nc_ctx* ctx, int direction, const unsigned char* buf, size_t len) {
    if (!ctx || !ctx->hexdump_enabled || ctx->hexdump_fd <= 0 || !buf || len == 0)
        return;

    uint64_t base = direction == 0 ? ctx->hexdump_sent_off : ctx->hexdump_recv_off;
    char dir = direction == 0 ? '>' : '<';

    for (size_t off = 0; off < len; off += 16) {
        size_t chunk = len - off;
        if (chunk > 16)
            chunk = 16;

        char line[96];
        int pos = snprintf(line, sizeof(line), "%c %08llx ", dir, (unsigned long long)(base + off));

        for (size_t i = 0; i < 16; i++) {
            if (i < chunk)
                pos += snprintf(line + pos, sizeof(line) - (size_t)pos, "%02x ", buf[off + i]);
            else
                pos += snprintf(line + pos, sizeof(line) - (size_t)pos, "   ");
        }

        pos += snprintf(line + pos, sizeof(line) - (size_t)pos, "# ");
        for (size_t i = 0; i < chunk && pos < (int)sizeof(line) - 1; i++) {
            unsigned char c = buf[off + i];
            line[pos++] = isprint(c) ? (char)c : '.';
        }
        line[pos++] = '\n';
        (void)write(ctx->hexdump_fd, line, (size_t)pos);
    }

    if (direction == 0)
        ctx->hexdump_sent_off += len;
    else
        ctx->hexdump_recv_off += len;
}
