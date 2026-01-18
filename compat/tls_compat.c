#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "tls.h"

struct tls_config {
    char* ca_file;
    char* ca_path;
    char* cert_file;
    char* key_file;
    char* ciphers;
    char* alpn;
    uint32_t protocols;
    int verify_cert;
    int verify_name;
    int verify_client;
    int verify_client_optional;
    int ocsp_require_stapling;
    int dgram;
    char* error;
};

struct tls {
    struct tls_config* config;
    SSL_CTX* ctx;
    SSL* ssl;
    int socket;
    int server_mode;
    char* error;
    int state;
};

static void set_error(struct tls* ctx, const char* msg) {
    free(ctx->error);
    ctx->error = strdup(msg);
}

int tls_init(void) {
    OPENSSL_init_ssl(0, NULL);
    return 0;
}

struct tls_config* tls_config_new(void) {
    struct tls_config* c = calloc(1, sizeof(*c));
    if (c) {
        c->verify_cert = 1;
        c->verify_name = 1;
        c->protocols = TLS_PROTOCOLS_DEFAULT;
    }
    return c;
}

void tls_config_free(struct tls_config* c) {
    if (!c)
        return;
    free(c->ca_file);
    free(c->ca_path);
    free(c->cert_file);
    free(c->key_file);
    free(c->ciphers);
    free(c->alpn);
    free(c->error);
    free(c);
}

const char* tls_config_error(struct tls_config* c) {
    return c->error;
}

int tls_config_set_ca_file(struct tls_config* c, const char* file) {
    free(c->ca_file);
    c->ca_file = strdup(file);
    return 0;
}

int tls_config_set_ca_path(struct tls_config* c, const char* path) {
    free(c->ca_path);
    c->ca_path = strdup(path);
    return 0;
}

int tls_config_set_cert_file(struct tls_config* c, const char* file) {
    free(c->cert_file);
    c->cert_file = strdup(file);
    return 0;
}

int tls_config_set_key_file(struct tls_config* c, const char* file) {
    free(c->key_file);
    c->key_file = strdup(file);
    return 0;
}

int tls_config_set_ciphers(struct tls_config* c, const char* ciphers) {
    free(c->ciphers);
    c->ciphers = strdup(ciphers);
    return 0;
}

int tls_config_set_protocols(struct tls_config* c, uint32_t protocols) {
    c->protocols = protocols;
    return 0;
}

int tls_config_set_alpn(struct tls_config* c, const char* alpn) {
    free(c->alpn);
    c->alpn = strdup(alpn);
    return 0;
}

int tls_config_set_dgram(struct tls_config* c, int dgram) {
    c->dgram = dgram;
    return 0;
}

int tls_config_set_ocsp_staple_file(struct tls_config* c, const char* file) {
    /* Not implemented yet */
    (void)c;
    (void)file;
    return 0;
}

void tls_config_insecure_noverifycert(struct tls_config* c) {
    c->verify_cert = 0;
}

void tls_config_insecure_noverifyname(struct tls_config* c) {
    c->verify_name = 0;
}

void tls_config_verify_client(struct tls_config* c) {
    c->verify_client = 1;
}

void tls_config_verify_client_optional(struct tls_config* c) {
    c->verify_client_optional = 1;
}

void tls_config_ocsp_require_stapling(struct tls_config* c) {
    c->ocsp_require_stapling = 1;
}

int tls_config_parse_protocols(uint32_t* protocols, const char* protostr) {
    *protocols = 0;
    if (strstr(protostr, "tlsv1.0"))
        *protocols |= TLS_PROTOCOL_TLSv1_0;
    if (strstr(protostr, "tlsv1.1"))
        *protocols |= TLS_PROTOCOL_TLSv1_1;
    if (strstr(protostr, "tlsv1.2"))
        *protocols |= TLS_PROTOCOL_TLSv1_2;
    if (strstr(protostr, "tlsv1.3"))
        *protocols |= TLS_PROTOCOL_TLSv1_3;
    if (strcasecmp(protostr, "all") == 0)
        *protocols = TLS_PROTOCOLS_ALL;
    if (strcasecmp(protostr, "default") == 0)
        *protocols = TLS_PROTOCOLS_DEFAULT;
    return 0;
}

struct tls* tls_client(void) {
    struct tls* ctx = calloc(1, sizeof(*ctx));
    if (ctx)
        ctx->server_mode = 0;
    return ctx;
}

struct tls* tls_server(void) {
    struct tls* ctx = calloc(1, sizeof(*ctx));
    if (ctx)
        ctx->server_mode = 1;
    return ctx;
}

void tls_free(struct tls* ctx) {
    if (!ctx)
        return;
    if (ctx->ssl)
        SSL_free(ctx->ssl);
    if (ctx->ctx)
        SSL_CTX_free(ctx->ctx);
    free(ctx->error);
    free(ctx);
}

const char* tls_error(struct tls* ctx) {
    return ctx->error;
}

int tls_configure(struct tls* ctx, struct tls_config* config) {
    const SSL_METHOD* method;

    if (config->dgram) {
        method = ctx->server_mode ? DTLS_server_method() : DTLS_client_method();
    }
    else {
        method = ctx->server_mode ? TLS_server_method() : TLS_client_method();
    }

    ctx->ctx = SSL_CTX_new(method);
    if (!ctx->ctx) {
        set_error(ctx, "SSL_CTX_new failed");
        return -1;
    }

    if (config->ca_file || config->ca_path) {
        if (!SSL_CTX_load_verify_locations(ctx->ctx, config->ca_file, config->ca_path)) {
            set_error(ctx, "Failed to load CA locations");
            return -1;
        }
    }
    else {
        SSL_CTX_set_default_verify_paths(ctx->ctx);
    }

    if (config->cert_file && config->key_file) {
        if (SSL_CTX_use_certificate_chain_file(ctx->ctx, config->cert_file) <= 0) {
            set_error(ctx, "Failed to load cert file");
            return -1;
        }
        if (SSL_CTX_use_PrivateKey_file(ctx->ctx, config->key_file, SSL_FILETYPE_PEM) <= 0) {
            set_error(ctx, "Failed to load key file");
            return -1;
        }
    }

    /* Protocols - simplified mapping */
    long options = 0;
    if (!(config->protocols & TLS_PROTOCOL_TLSv1_0))
        options |= SSL_OP_NO_TLSv1;
    if (!(config->protocols & TLS_PROTOCOL_TLSv1_1))
        options |= SSL_OP_NO_TLSv1_1;
    if (!(config->protocols & TLS_PROTOCOL_TLSv1_2))
        options |= SSL_OP_NO_TLSv1_2;
#ifdef SSL_OP_NO_TLSv1_3
    if (!(config->protocols & TLS_PROTOCOL_TLSv1_3))
        options |= SSL_OP_NO_TLSv1_3;
#endif
    SSL_CTX_set_options(ctx->ctx, options);

    if (config->ciphers) {
        SSL_CTX_set_cipher_list(ctx->ctx, config->ciphers);
    }

    int verify_mode = SSL_VERIFY_NONE;
    if (ctx->server_mode) {
        if (config->verify_client)
            verify_mode |= SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        if (config->verify_client_optional)
            verify_mode |= SSL_VERIFY_PEER;
    }
    else {
        if (config->verify_cert)
            verify_mode |= SSL_VERIFY_PEER;
    }
    SSL_CTX_set_verify(ctx->ctx, verify_mode, NULL);

    /* ALPN */
    if (config->alpn) {
        /* This is a bit simplified, ALPN string parsing needed normally */
        /* For netcat it is usually comma separated? libtls expects comma separated. OpenSSL wants length-prefixed */
        /* We will skip complex ALPN parsing for now as it's complex to implement correctly in a short shim */
    }

    return 0;
}

int tls_connect_socket(struct tls* ctx, int s, const char* servername) {
    ctx->socket = s;
    ctx->ssl = SSL_new(ctx->ctx);
    if (!ctx->ssl) {
        set_error(ctx, "SSL_new failed");
        return -1;
    }
    SSL_set_fd(ctx->ssl, s);
    if (servername) {
        SSL_set_tlsext_host_name(ctx->ssl, servername);
    }
    /* We don't do connect here yet, driven by handshake */
    return 0;
}

int tls_accept_socket(struct tls* ctx, struct tls** cctx, int s) {
    struct tls* new_ctx = tls_server();
    if (!new_ctx)
        return -1;

    /* Share config logic/ctx (re-creating for simplicity here, ideally share or clone) */
    /* Netcat usage implies main ctx is just a template? No, netcat calls tls_setup_server which calls tls_server() */
    /* Wait, tls_accept_socket takes 'ctx' which is the listening context, and produces 'cctx' */

    new_ctx->ctx = ctx->ctx; /* Use same SSL_CTX? Reference counting? */
    /* OpenSSL SSL_CTX is refcounted. We should up-ref or just use it. */
    SSL_CTX_up_ref(ctx->ctx);

    new_ctx->socket = s;
    new_ctx->ssl = SSL_new(new_ctx->ctx);
    if (!new_ctx->ssl) {
        tls_free(new_ctx);
        return -1;
    }
    SSL_set_fd(new_ctx->ssl, s);

    *cctx = new_ctx;
    return 0;
}

int tls_handshake(struct tls* ctx) {
    int ret;
    if (ctx->server_mode) {
        ret = SSL_accept(ctx->ssl);
    }
    else {
        ret = SSL_connect(ctx->ssl);
    }

    if (ret == 1)
        return 0;

    int err = SSL_get_error(ctx->ssl, ret);
    if (err == SSL_ERROR_WANT_READ)
        return TLS_WANT_POLLIN;
    if (err == SSL_ERROR_WANT_WRITE)
        return TLS_WANT_POLLOUT;

    char msg[256];
    ERR_error_string_n(ERR_get_error(), msg, sizeof(msg));
    set_error(ctx, msg);
    return -1;
}

ssize_t tls_read(struct tls* ctx, void* buf, size_t buflen) {
    int ret = SSL_read(ctx->ssl, buf, buflen);
    if (ret > 0)
        return ret;

    int err = SSL_get_error(ctx->ssl, ret);
    if (err == SSL_ERROR_WANT_READ)
        return TLS_WANT_POLLIN;
    if (err == SSL_ERROR_WANT_WRITE)
        return TLS_WANT_POLLOUT;

    if (ret == 0)
        return 0; /* EOF */

    char msg[256];
    ERR_error_string_n(ERR_get_error(), msg, sizeof(msg));
    set_error(ctx, msg);
    return -1;
}

ssize_t tls_write(struct tls* ctx, const void* buf, size_t buflen) {
    int ret = SSL_write(ctx->ssl, buf, buflen);
    if (ret > 0)
        return ret;

    int err = SSL_get_error(ctx->ssl, ret);
    if (err == SSL_ERROR_WANT_READ)
        return TLS_WANT_POLLIN;
    if (err == SSL_ERROR_WANT_WRITE)
        return TLS_WANT_POLLOUT;

    char msg[256];
    ERR_error_string_n(ERR_get_error(), msg, sizeof(msg));
    set_error(ctx, msg);
    return -1;
}

int tls_close(struct tls* ctx) {
    if (ctx->ssl)
        SSL_shutdown(ctx->ssl);
    return 0;
}

/* Certificate inspection stubs */
int tls_peer_cert_provided(struct tls* ctx) {
    return SSL_get_peer_certificate(ctx->ssl) != NULL;
}

const char* tls_peer_cert_hash(struct tls* ctx) {
    (void)ctx;
    /* Not implemented */
    return NULL;
}

const char* tls_peer_cert_subject(struct tls* ctx) {
    static char buf[1024];
    X509* cert = SSL_get_peer_certificate(ctx->ssl);
    if (!cert)
        return NULL;
    X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf));
    return buf;
}

const char* tls_peer_cert_issuer(struct tls* ctx) {
    static char buf[1024];
    X509* cert = SSL_get_peer_certificate(ctx->ssl);
    if (!cert)
        return NULL;
    X509_NAME_oneline(X509_get_issuer_name(cert), buf, sizeof(buf));
    return buf;
}

int tls_peer_cert_contains_name(struct tls* ctx, const char* name) {
    /* Not implemented - simplified check */
    (void)ctx;
    (void)name;
    return 0;
}

const char* tls_conn_version(struct tls* ctx) {
    return SSL_get_version(ctx->ssl);
}

const char* tls_conn_cipher(struct tls* ctx) {
    return SSL_get_cipher_name(ctx->ssl);
}

const char* tls_default_ca_cert_file(void) {
    return "/etc/ssl/cert.pem";
}

/* Stubs for OCSP and others not strictly critical for basic netcat function */
const char* tls_peer_ocsp_url(struct tls* ctx) {
    (void)ctx;
    return NULL;
}
int tls_peer_ocsp_response_status(struct tls* ctx) {
    (void)ctx;
    return 0;
}
const char* tls_peer_ocsp_result(struct tls* ctx) {
    (void)ctx;
    return NULL;
}
int tls_peer_ocsp_cert_status(struct tls* ctx) {
    (void)ctx;
    return 0;
}
int tls_peer_ocsp_crl_reason(struct tls* ctx) {
    (void)ctx;
    return 0;
}
time_t tls_peer_ocsp_this_update(struct tls* ctx) {
    (void)ctx;
    return 0;
}
time_t tls_peer_ocsp_next_update(struct tls* ctx) {
    (void)ctx;
    return 0;
}
time_t tls_peer_ocsp_revocation_time(struct tls* ctx) {
    (void)ctx;
    return 0;
}
const char* tls_conn_alpn_selected(struct tls* ctx) {
    (void)ctx;
    return NULL;
}
time_t tls_peer_cert_notbefore(struct tls* ctx) {
    (void)ctx;
    return 0;
}
time_t tls_peer_cert_notafter(struct tls* ctx) {
    (void)ctx;
    return 0;
}
const uint8_t* tls_peer_cert_chain_pem(struct tls* ctx, size_t* len) {
    (void)ctx;
    (void)len;
    return NULL;
}
