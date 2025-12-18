#include "openbsd_compat.h"
#include <errno.h>
#include <limits.h>
#include <stdlib.h>

#if !defined(HAVE_BSD_STDLIB_H) && !defined(HAVE_STRTONUM)

#define INVALID 1
#define TOOSMALL 2
#define TOOLARGE 3

long long strtonum(const char* numstr, long long minval, long long maxval, const char** errstrp) {
    long long ll = 0;
    char* ep;
    int error = 0;
    struct errval {
        const char* errstr;
        int err;
    } ev[4] = {
        {NULL, 0},
        {"invalid", INVALID},
        {"too small", TOOSMALL},
        {"too large", TOOLARGE},
    };

    ev[0].err = errno;
    errno = 0;
    if (minval > maxval)
        error = INVALID;
    else {
        ll = strtoll(numstr, &ep, 10);
        if (numstr == ep || *ep != '\0')
            error = INVALID;
        else if ((ll == LLONG_MIN && errno == ERANGE) || ll < minval)
            error = TOOSMALL;
        else if ((ll == LLONG_MAX && errno == ERANGE) || ll > maxval)
            error = TOOLARGE;
    }
    if (errstrp != NULL)
        *errstrp = ev[error].errstr;
    errno = ev[0].err;
    if (error)
        ll = 0;

    return (ll);
}

#endif
