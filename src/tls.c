#include "netcat.h"

int timeout_tls(int s, struct tls* tls_ctx, int (*func)(struct tls*)) {
    struct pollfd pfd;
    int ret;

    while ((ret = func(tls_ctx)) != 0) {
        if (ret == TLS_WANT_POLLIN)
            pfd.events = POLLIN;
        else if (ret == TLS_WANT_POLLOUT)
            pfd.events = POLLOUT;
        else
            break;
        pfd.fd = s;
        if ((ret = poll(&pfd, 1, timeout)) == 1)
            continue;
        else if (ret == 0) {
            errno = ETIMEDOUT;
            ret = -1;
            break;
        }
        else
            err(1, "poll failed");
    }

    return ret;
}

void tls_setup_client(struct tls* tls_ctx, int s, char* host) {
    const char* errstr;

    if (tls_connect_socket(tls_ctx, s, tls_expectname ? tls_expectname : host) == -1) {
        errx(1, "tls connection failed (%s)", tls_error(tls_ctx));
    }
    if (timeout_tls(s, tls_ctx, tls_handshake) == -1) {
        if ((errstr = tls_error(tls_ctx)) == NULL)
            errstr = strerror(errno);
        errx(1, "tls handshake failed (%s)", errstr);
    }
    if (vflag)
        report_tls(tls_ctx, host);
    if (tls_expecthash &&
        (tls_peer_cert_hash(tls_ctx) == NULL || strcmp(tls_expecthash, tls_peer_cert_hash(tls_ctx)) != 0))
        errx(1, "peer certificate is not %s", tls_expecthash);
    if (Zflag) {
        save_peer_cert(tls_ctx, Zflag);
        if (Zflag != stderr && (fclose(Zflag) != 0))
            err(1, "fclose failed saving peer cert");
    }
}

struct tls* tls_setup_server(struct tls* tls_ctx, int connfd, char* host) {
    struct tls* tls_cctx;
    const char* errstr;

    if (tls_accept_socket(tls_ctx, &tls_cctx, connfd) == -1) {
        warnx("tls accept failed (%s)", tls_error(tls_ctx));
    }
    else if (timeout_tls(connfd, tls_cctx, tls_handshake) == -1) {
        if ((errstr = tls_error(tls_cctx)) == NULL)
            errstr = strerror(errno);
        warnx("tls handshake failed (%s)", errstr);
    }
    else {
        int gotcert = tls_peer_cert_provided(tls_cctx);

        if (vflag && gotcert)
            report_tls(tls_cctx, host);
        if ((TLSopt & TLS_CCERT) && !gotcert)
            warnx("No client certificate provided");
        else if (gotcert && tls_expecthash &&
                 (tls_peer_cert_hash(tls_ctx) == NULL || strcmp(tls_expecthash, tls_peer_cert_hash(tls_ctx)) != 0))
            warnx("peer certificate is not %s", tls_expecthash);
        else if (gotcert && tls_expectname && (!tls_peer_cert_contains_name(tls_cctx, tls_expectname)))
            warnx("name (%s) not found in client cert", tls_expectname);
        else {
            return tls_cctx;
        }
    }
    return NULL;
}

int process_tls_opt(char* s, int* flags) {
    size_t len;
    char* v;

    const struct tlskeywords {
        const char* keyword;
        int flag;
        char** value;
    } *t, tlskeywords[] = {
              {"alpn", -1, &tls_alpn},           {"ciphers", -1, &tls_ciphers},
              {"clientcert", TLS_CCERT, NULL},   {"muststaple", TLS_MUSTSTAPLE, NULL},
              {"noname", TLS_NONAME, NULL},      {"noverify", TLS_NOVERIFY, NULL},
              {"protocols", -1, &tls_protocols}, {NULL, -1, NULL},
          };

    len = strlen(s);
    if ((v = strchr(s, '=')) != NULL) {
        len = v - s;
        v++;
    }

    for (t = tlskeywords; t->keyword != NULL; t++) {
        if (strlen(t->keyword) == len && strncmp(s, t->keyword, len) == 0) {
            if (t->value != NULL) {
                if (v == NULL)
                    errx(1, "invalid tls value `%s'", s);
                *t->value = v;
            }
            else {
                if (v != NULL)
                    errx(1, "invalid tls value `%s'", s);
                *flags |= t->flag;
            }
            return 1;
        }
    }
    return 0;
}

void save_peer_cert(struct tls* tls_ctx, FILE* fp) {
    const char* pem;
    size_t plen;

    if ((pem = (const char*)tls_peer_cert_chain_pem(tls_ctx, &plen)) == NULL)
        errx(1, "Can't get peer certificate");
    if (fprintf(fp, "%.*s", (int)plen, pem) < 0)
        err(1, "unable to save peer cert");
    if (fflush(fp) != 0)
        err(1, "unable to flush peer cert");
}

void report_tls(struct tls* tls_ctx, char* host) {
    time_t t;
    const char *alpn_proto, *ocsp_url;

    if (jflag) {
        char tbuf[32];
        time_t now;
        struct tm* tm_info;

        time(&now);
        tm_info = gmtime(&now);
        strftime(tbuf, sizeof(tbuf), "%Y-%m-%dT%H:%M:%SZ", tm_info);

        fprintf(stderr,
                "{\"timestamp\":\"%s\",\"level\":\"info\",\"event\":\"tls_handshake_succeeded\",\"host\":\"%s\","
                "\"version\":\"%s\",\"cipher\":\"%s\"",
                tbuf, host, tls_conn_version(tls_ctx), tls_conn_cipher(tls_ctx));
        if (tls_peer_cert_subject(tls_ctx))
            fprintf(stderr, ",\"subject\":\"%s\"", tls_peer_cert_subject(tls_ctx));
        if (tls_peer_cert_issuer(tls_ctx))
            fprintf(stderr, ",\"issuer\":\"%s\"", tls_peer_cert_issuer(tls_ctx));
        if (tls_peer_cert_hash(tls_ctx))
            fprintf(stderr, ",\"cert_hash\":\"%s\"", tls_peer_cert_hash(tls_ctx));
        if ((alpn_proto = tls_conn_alpn_selected(tls_ctx)) != NULL)
            fprintf(stderr, ",\"alpn\":\"%s\"", alpn_proto);
        fprintf(stderr, "}\n");
    }
    else {
        fprintf(stderr, "TLS handshake negotiated %s/%s with host %s\n", tls_conn_version(tls_ctx),
                tls_conn_cipher(tls_ctx), host);
        fprintf(stderr, "Peer name: %s\n", tls_expectname ? tls_expectname : host);
        if (tls_peer_cert_subject(tls_ctx))
            fprintf(stderr, "Subject: %s\n", tls_peer_cert_subject(tls_ctx));
        if (tls_peer_cert_issuer(tls_ctx))
            fprintf(stderr, "Issuer: %s\n", tls_peer_cert_issuer(tls_ctx));
        if ((t = tls_peer_cert_notbefore(tls_ctx)) != -1)
            fprintf(stderr, "Valid From: %s", ctime(&t));
        if ((t = tls_peer_cert_notafter(tls_ctx)) != -1)
            fprintf(stderr, "Valid Until: %s", ctime(&t));
        if (tls_peer_cert_hash(tls_ctx))
            fprintf(stderr, "Cert Hash: %s\n", tls_peer_cert_hash(tls_ctx));
        ocsp_url = tls_peer_ocsp_url(tls_ctx);
        if (ocsp_url != NULL)
            fprintf(stderr, "OCSP URL: %s\n", ocsp_url);
        switch (tls_peer_ocsp_response_status(tls_ctx)) {
            case TLS_OCSP_RESPONSE_SUCCESSFUL:
                fprintf(stderr, "OCSP Stapling: %s\n",
                        tls_peer_ocsp_result(tls_ctx) == NULL ? "" : tls_peer_ocsp_result(tls_ctx));
                fprintf(stderr, "  response_status=%d cert_status=%d crl_reason=%d\n",
                        tls_peer_ocsp_response_status(tls_ctx), tls_peer_ocsp_cert_status(tls_ctx),
                        tls_peer_ocsp_crl_reason(tls_ctx));
                t = tls_peer_ocsp_this_update(tls_ctx);
                fprintf(stderr, "  this update: %s", t != -1 ? ctime(&t) : "\n");
                t = tls_peer_ocsp_next_update(tls_ctx);
                fprintf(stderr, "  next update: %s", t != -1 ? ctime(&t) : "\n");
                t = tls_peer_ocsp_revocation_time(tls_ctx);
                fprintf(stderr, "  revocation: %s", t != -1 ? ctime(&t) : "\n");
                break;
            case -1:
                break;
            default:
                fprintf(stderr, "OCSP Stapling:  failure - response_status %d (%s)\n",
                        tls_peer_ocsp_response_status(tls_ctx),
                        tls_peer_ocsp_result(tls_ctx) == NULL ? "" : tls_peer_ocsp_result(tls_ctx));
                break;
        }
        if ((alpn_proto = tls_conn_alpn_selected(tls_ctx)) != NULL)
            fprintf(stderr, "Application Layer Protocol: %s\n", alpn_proto);
    }
}
