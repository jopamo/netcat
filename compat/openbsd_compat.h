#ifndef OPENBSD_COMPAT_H
#define OPENBSD_COMPAT_H

#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* strtonum */
#if defined(HAVE_BSD_STDLIB_H)
#include <bsd/stdlib.h>
#elif !defined(HAVE_STRTONUM)
long long strtonum(const char* numstr, long long minval, long long maxval, const char** errstrp);
#endif

/* pledge/unveil */
#ifndef HAVE_PLEDGE
#define pledge(promises, execpromises) (0)
#endif

#ifndef HAVE_UNVEIL
#define unveil(path, permissions) (0)
#endif

/* setrtable */
#ifndef HAVE_SETRTABLE
#define setrtable(id) (0)
#endif
#ifndef RT_TABLEID_MAX
#define RT_TABLEID_MAX 255
#endif

/* SO_BINDANY */
#ifndef SO_BINDANY
#define SO_BINDANY 0
#endif

/* IPTOS_DSCP constants */
#ifndef IPTOS_DSCP_CS0
#define IPTOS_DSCP_CS0 0x00
#endif
#ifndef IPTOS_DSCP_CS1
#define IPTOS_DSCP_CS1 0x08
#endif
#ifndef IPTOS_DSCP_CS2
#define IPTOS_DSCP_CS2 0x10
#endif
#ifndef IPTOS_DSCP_CS3
#define IPTOS_DSCP_CS3 0x18
#endif
#ifndef IPTOS_DSCP_CS4
#define IPTOS_DSCP_CS4 0x20
#endif
#ifndef IPTOS_DSCP_CS5
#define IPTOS_DSCP_CS5 0x28
#endif
#ifndef IPTOS_DSCP_CS6
#define IPTOS_DSCP_CS6 0x30
#endif
#ifndef IPTOS_DSCP_CS7
#define IPTOS_DSCP_CS7 0x38
#endif

#endif /* OPENBSD_COMPAT_H */
