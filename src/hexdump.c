#include "netcat.h"
#include <stdio.h>
#include <ctype.h>

void hexdump(FILE* fp, const char* prefix, const unsigned char* buf, size_t len, size_t total) {
    size_t i, j;
    for (i = 0; i < len; i += 16) {
        fprintf(fp, "%s %08zx ", prefix, total + i);
        for (j = 0; j < 16; j++) {
            if (i + j < len)
                fprintf(fp, "%02x ", buf[i + j]);
            else
                fprintf(fp, "   ");
            if (j == 7)
                fprintf(fp, " ");
        }
        fprintf(fp, " |");
        for (j = 0; j < 16; j++) {
            if (i + j < len)
                fprintf(fp, "%c", isprint(buf[i + j]) ? buf[i + j] : '.');
            else
                fprintf(fp, " ");
        }
        fprintf(fp, "|\n");
    }
    fflush(fp);
}
