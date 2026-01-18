#ifndef NETCAT_PCAP_H
#define NETCAT_PCAP_H

#include <stddef.h>

void pcap_open(int fd, const char* path);
void pcap_log(int fd, const unsigned char* buf, size_t len, int direction);
void pcap_close(void);

#endif
