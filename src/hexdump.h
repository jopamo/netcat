#ifndef HEXDUMP_H
#define HEXDUMP_H

#include <stdint.h>

void nc_hexdump_write(int fd, const unsigned char* buf, size_t len, uint64_t base);

#endif  // HEXDUMP_H