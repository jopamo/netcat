/* $OpenBSD: netcat.c,v 1.237 2025/12/06 09:48:30 phessler Exp $ */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <tls.h>
#include <unistd.h>

#include "atomicio.h"
#include "openbsd_compat.h"

#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif

#define PORT_MAX 65535
#define UNIX_DG_TMP_SOCKET_SIZE 19

#define POLL_STDIN 0
#define POLL_NETOUT 1
#define POLL_NETIN 2
#define POLL_STDOUT 3
#define BUFSIZE 16384

#define TLS_NOVERIFY (1 << 1)
#define TLS_NONAME (1 << 2)
#define TLS_CCERT (1 << 3)
#define TLS_MUSTSTAPLE (1 << 4)

/* Command Line Options */
extern int dflag;          /* detached, no stdin */
extern int Fflag;          /* fdpass sock to stdout */
extern unsigned int iflag; /* Interval Flag */
extern int kflag;          /* More than one connect */
extern int lflag;          /* Bind to local port */
extern int jflag;          /* JSON output */
extern char* pcapfile;     /* PCAP file path */
extern int proxy_proto;    /* PROXY protocol server */
extern int send_proxy;     /* PROXY protocol client */
extern FILE* hex_fp;       /* Hex dump file pointer */
extern char* hex_path;     /* Hex dump file path */
extern int Nflag;          /* shutdown() network socket */
extern int fuzz_tcp;       /* Fuzz TCP with random data */
extern int fuzz_udp;       /* Fuzz UDP with random data */
extern int tfoflag;        /* TCP Fast Open */
extern int mptcpflag;      /* Multipath TCP */
extern int spliceflag;     /* Zero-copy splice */
extern int sockmark;       /* SO_MARK */
extern int sockpriority;   /* SO_PRIORITY */
extern int nflag;          /* Don't do name look up */
extern char* Pflag;        /* Proxy username */
extern char* pflag;        /* Localport flag */
extern int rflag;          /* Random ports flag */
extern char* sflag;        /* Source Address */
extern char* iface;        /* Interface to bind to */
extern int transparent;    /* IP_TRANSPARENT */
extern int uflag;          /* UDP - Default to TCP */
extern int vflag;          /* Verbosity */
extern int xflag;          /* Socks proxy */
extern int zflag;          /* Port Scan Flag */
extern int Dflag;          /* sodebug */
extern int Iflag;          /* TCP receive buffer size */
extern int Oflag;          /* TCP send buffer size */
extern int Tflag;          /* IP Type of Service */
extern int rtableid;

extern int usetls;           /* use TLS */
extern const char* Cflag;    /* Public cert file */
extern const char* Kflag;    /* Private key file */
extern const char* oflag;    /* OCSP stapling file */
extern const char* Rflag;    /* Root CA file */
extern int tls_cachanged;    /* Using non-default CA file */
extern int TLSopt;           /* TLS options */
extern char* exec_path;      /* program to exec */
extern char* tls_expectname; /* required name in peer cert */
extern char* tls_expecthash; /* required hash of peer cert */
extern char* tls_ciphers;    /* TLS ciphers */
extern char* tls_protocols;  /* TLS protocols */
extern char* tls_alpn;       /* TLS ALPN */
extern FILE* Zflag;          /* file to save peer cert */

extern int recvcount, recvlimit;
extern int timeout;
extern int family;
extern char* portlist[PORT_MAX + 1];
extern char* unix_dg_tmp_socket;
extern int ttl;
extern int minttl;

extern char* vsock_cid;
extern char* vsock_port;

int strtoport(char* portstr, int udp);
void build_ports(char*);
void help(void) __attribute__((noreturn));
int local_listen(const char*, const char*, struct addrinfo);
void readwrite(int, struct tls*);
void fdpass(int nfd) __attribute__((noreturn));
int remote_connect(const char*, const char*, struct addrinfo, char*);
int timeout_tls(int, struct tls*, int (*)(struct tls*));
int timeout_connect(int, const struct sockaddr*, socklen_t);
int socks_connect(const char*,
                  const char*,
                  struct addrinfo,
                  const char*,
                  const char*,
                  struct addrinfo,
                  int,
                  const char*);
int udptest(int);
void connection_info(const char*, const char*, const char*, const char*);
int unix_bind(char*, int);
int unix_connect(char*);
int unix_listen(char*);
int vsock_listen(const char*, const char*);
int vsock_connect(const char*, const char*);
void set_common_sockopts(int, int);
int process_tos_opt(char*, int*);
int process_tls_opt(char*, int*);
void save_peer_cert(struct tls* _tls_ctx, FILE* _fp);
void report_sock(const char*, const struct sockaddr*, socklen_t, char*);
void report_tls(struct tls* tls_ctx, char* host);
void vsock_report(const char*, const char*, int);
#ifdef GAPING_SECURITY_HOLE
void spawn_exec(int);
#endif
void usage(int);
void hexdump(FILE* fp, const char* prefix, const unsigned char* buf, size_t len, size_t total);
ssize_t drainbuf(int, unsigned char*, size_t*, struct tls*, int);
ssize_t fillbuf(int, unsigned char*, size_t*, struct tls*, int);
void tls_setup_client(struct tls*, int, char*);
struct tls* tls_setup_server(struct tls*, int, char*);
