#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define NC_BIGSIZ 8192
#define NC_MAXHOSTNAMELEN 256

enum nc_proto { NC_TCP, NC_UDP };

// Forward declaration for internal buffer types
struct io_buf;

struct nc_ctx {
    // Socket state
    int netfd;
    int hexdump_fd;

    // Protocol mode
    enum nc_proto proto;
    bool listen_mode;

    // Options/flags (matching original o_* globals)
    bool numeric_only;
    int verbose;
    bool allow_broadcast;
    bool zero_io;
    bool telnet;
    bool hexdump_enabled;
    bool random_ports;
    bool all_a_records;     // -a (likely to be removed)
    bool holler_to_stderr;  // original o_holler_stderr

    // Timeouts and intervals
    unsigned int interval;  // -i line interval
    unsigned int timeout;   // -w connect/read timeout
    int quit_after_eof;     // -q seconds after stdin EOF (0=immediate, -1=disabled)

    // Counters
    uint64_t wrote_out;
    uint64_t wrote_net;

    // Exec feature
    const char* exec_prog;
    bool exec_use_sh;

    // Port scanning state
    bool single_mode;        // original Single flag (true = single port)
    unsigned int insaved;    // saved stdin buffer size for multi-mode
    unsigned short loport;   // low port in range
    unsigned short hiport;   // high port in range
    unsigned short curport;  // current port being tried
    unsigned short ourport;  // local source port
    char* randports;         // random port tracking array

    // Buffers (like original bigbuf_in/bigbuf_net)
    unsigned char* buf_stdin;
    unsigned char* buf_net;

    // Hexdump state
    unsigned char* stage;       // hexdump line buffer
    unsigned char hexnibs[20];  // hex digits

    // Address resolution results
    struct sockaddr_storage local_addr;
    struct sockaddr_storage remote_addr;
    socklen_t local_addrlen;
    socklen_t remote_addrlen;

    // For getaddrinfo results
    char remote_host[NC_MAXHOSTNAMELEN];
    char remote_service[64];

    // Port info (like original portpoop)
    char port_name[64];
    unsigned short port_num;

    // Logging
    FILE* log_out;

    // Internal buffers for I/O pump
    struct io_buf* to_net_buf;
    struct io_buf* to_out_buf;
};

// Context management
void nc_ctx_init(struct nc_ctx* ctx);
void nc_ctx_cleanup(struct nc_ctx* ctx);

// Logging and error handling
void nc_holler(struct nc_ctx* ctx, const char* fmt, ...);
void nc_bail(struct nc_ctx* ctx, const char* fmt, ...);
void nc_debug(struct nc_ctx* ctx, const char* fmt, ...);