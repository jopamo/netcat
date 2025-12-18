#ifndef RESOLVE_H
#define RESOLVE_H

#include "nc_ctx.h"
#include <sys/socket.h>
#include <netinet/in.h>

int nc_resolve_one(const char* host,
                   const char* service,
                   int family,
                   enum nc_proto proto,
                   struct sockaddr_storage* out,
                   socklen_t* out_len,
                   bool numeric_only);

int nc_reverse_name(const struct sockaddr* sa, socklen_t slen, char* host, size_t host_sz, bool numeric_only);
bool nc_forward_reverse_mismatch(const struct sockaddr_storage* target, socklen_t target_len, const char* reverse_host);

// Port and service resolution
unsigned short nc_resolve_port(struct nc_ctx* ctx, const char* port_str);
int nc_parse_port_range(struct nc_ctx* ctx, const char* range_str);
int nc_resolve_local_address(struct nc_ctx* ctx, const char* addr_str);

// Random port selection for scanning
int nc_random_ports_init(struct nc_ctx* ctx, unsigned short lo, unsigned short hi);
unsigned short nc_random_ports_next(struct nc_ctx* ctx);

// Sockaddr helpers
void nc_set_port(struct sockaddr_storage* ss, unsigned short port);
unsigned short nc_get_port(const struct sockaddr_storage* ss);

#endif  // RESOLVE_H
