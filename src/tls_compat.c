#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "mbedtls/error.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/timing.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509.h"
#include "mbedtls/private/ctr_drbg.h"
#include "mbedtls/private/entropy.h"
#include "psa/crypto.h"

#include "tls.h"

extern int vflag;

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
    int socket;
    int server_mode;
    int handshake_complete;
    int use_mbedtls_dtls;
    int mbedtls_initialized;
    int ca_initialized;
    mbedtls_x509_crt ca;
    mbedtls_ssl_context mssl;
    mbedtls_ssl_config mconf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_x509_crt cert;
    mbedtls_pk_context pkey;
    mbedtls_ssl_cookie_ctx cookie;
    mbedtls_timing_delay_context timer;
    char* servername;
    char* error;
    char** alpn_list;
    size_t alpn_count;
    char* peer_cert_hash;
    char* peer_cert_subject;
    char* peer_cert_issuer;
    unsigned char* peer_chain_pem;
    size_t peer_chain_pem_len;
};

static int psa_initialized;

static int entropy_urandom(void* data, unsigned char* output, size_t len, size_t* olen) {
    (void)data;

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }

    size_t done = 0;
    while (done < len) {
        ssize_t n = read(fd, output + done, len - done);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
        }
        if (n == 0) {
            close(fd);
            return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
        }
        done += (size_t)n;
    }

    close(fd);
    *olen = len;
    return 0;
}

static void set_error(struct tls* ctx, const char* msg) {
    free(ctx->error);
    ctx->error = strdup(msg);
}

static void set_config_error(struct tls_config* cfg, const char* msg) {
    free(cfg->error);
    cfg->error = strdup(msg);
}

static void clear_peer_cache(struct tls* ctx) {
    free(ctx->peer_cert_hash);
    ctx->peer_cert_hash = NULL;
    free(ctx->peer_cert_subject);
    ctx->peer_cert_subject = NULL;
    free(ctx->peer_cert_issuer);
    ctx->peer_cert_issuer = NULL;
    free(ctx->peer_chain_pem);
    ctx->peer_chain_pem = NULL;
    ctx->peer_chain_pem_len = 0;
}

static void free_alpn_list(struct tls* ctx) {
    if (!ctx->alpn_list)
        return;
    for (size_t i = 0; i < ctx->alpn_count; i++)
        free(ctx->alpn_list[i]);
    free(ctx->alpn_list);
    ctx->alpn_list = NULL;
    ctx->alpn_count = 0;
}

static int parse_alpn_list(struct tls* ctx, const char* alpn) {
    if (!alpn || *alpn == '\0')
        return 0;

    char* copy = strdup(alpn);
    if (!copy)
        return -1;

    size_t count = 0;
    char* p = copy;
    while (*p) {
        while (*p == ' ' || *p == ',')
            p++;
        if (*p == '\0')
            break;
        count++;
        while (*p && *p != ',')
            p++;
    }

    if (count == 0) {
        free(copy);
        return 0;
    }

    char** list = calloc(count + 1, sizeof(*list));
    if (!list) {
        free(copy);
        return -1;
    }

    p = copy;
    size_t idx = 0;
    while (*p) {
        while (*p == ' ' || *p == ',')
            p++;
        if (*p == '\0')
            break;
        char* start = p;
        while (*p && *p != ',')
            p++;
        if (*p)
            *p++ = '\0';
        list[idx] = strdup(start);
        if (!list[idx]) {
            for (size_t i = 0; i < idx; i++)
                free(list[i]);
            free(list);
            free(copy);
            return -1;
        }
        idx++;
    }

    free(copy);
    free_alpn_list(ctx);
    ctx->alpn_list = list;
    ctx->alpn_count = idx;
    return 0;
}

static void set_error_mbedtls(struct tls* ctx, int ret, const char* prefix) {
    char buf[128];
    char msg[200];
    mbedtls_strerror(ret, buf, sizeof(buf));
    snprintf(msg, sizeof(msg), "%s: %s", prefix, buf);
    set_error(ctx, msg);
}

static int load_ca_bundle(struct tls* ctx, struct tls_config* config) {
    if (!ctx->ca_initialized) {
        mbedtls_x509_crt_init(&ctx->ca);
        ctx->ca_initialized = 1;
    }
    if (config->ca_file) {
        int ret = mbedtls_x509_crt_parse_file(&ctx->ca, config->ca_file);
        if (ret != 0) {
            set_error_mbedtls(ctx, ret, "Failed to load CA file");
            return -1;
        }
    }
    if (config->ca_path) {
        int ret = mbedtls_x509_crt_parse_path(&ctx->ca, config->ca_path);
        if (ret != 0) {
            set_error_mbedtls(ctx, ret, "Failed to load CA path");
            return -1;
        }
    }
    if (!config->ca_file && !config->ca_path) {
        int loaded = 0;
        if (mbedtls_x509_crt_parse_file(&ctx->ca, "/etc/ssl/certs/ca-certificates.crt") == 0)
            loaded = 1;
        if (!loaded && mbedtls_x509_crt_parse_file(&ctx->ca, "/etc/pki/tls/certs/ca-bundle.crt") == 0)
            loaded = 1;
        if (!loaded && mbedtls_x509_crt_parse_file(&ctx->ca, "/etc/ssl/cert.pem") == 0)
            loaded = 1;
        if (!loaded && mbedtls_x509_crt_parse_path(&ctx->ca, "/etc/ssl/certs") == 0)
            loaded = 1;
        if (!loaded) {
            set_error(ctx, "No CA bundle found for verification");
            return -1;
        }
    }
    return 0;
}

static int stream_send(void* ctx, const unsigned char* buf, size_t len) {
    int fd = *(int*)ctx;
    int flags = MSG_DONTWAIT;
#ifdef MSG_NOSIGNAL
    flags |= MSG_NOSIGNAL;
#endif
    ssize_t n = send(fd, buf, len, flags);
    if (n >= 0)
        return (int)n;
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

static int stream_recv(void* ctx, unsigned char* buf, size_t len) {
    int fd = *(int*)ctx;
    ssize_t n = recv(fd, buf, len, MSG_DONTWAIT);
    if (n >= 0)
        return (int)n;
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        return MBEDTLS_ERR_SSL_WANT_READ;
    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int append_pem_cert(unsigned char** out, size_t* out_len, const unsigned char* der, size_t der_len) {
    const char* header = "-----BEGIN CERTIFICATE-----\n";
    const char* footer = "-----END CERTIFICATE-----\n";

    size_t b64_len = ((der_len + 2) / 3) * 4;
    char* b64 = malloc(b64_len ? b64_len : 1);
    if (!b64)
        return -1;

    size_t i = 0;
    size_t o = 0;
    while (i < der_len) {
        size_t rem = der_len - i;
        unsigned char a = der[i++];
        unsigned char b = rem > 1 ? der[i++] : 0;
        unsigned char c = rem > 2 ? der[i++] : 0;

        unsigned int triple = (a << 16) | (b << 8) | c;
        b64[o++] = b64_table[(triple >> 18) & 0x3f];
        b64[o++] = b64_table[(triple >> 12) & 0x3f];
        b64[o++] = rem > 1 ? b64_table[(triple >> 6) & 0x3f] : '=';
        b64[o++] = rem > 2 ? b64_table[triple & 0x3f] : '=';
    }

    size_t line_count = (b64_len + 63) / 64;
    size_t pem_len = strlen(header) + b64_len + line_count + strlen(footer);

    unsigned char* next = realloc(*out, *out_len + pem_len + 1);
    if (!next) {
        free(b64);
        return -1;
    }
    *out = next;

    unsigned char* dst = *out + *out_len;
    memcpy(dst, header, strlen(header));
    dst += strlen(header);

    size_t written = 0;
    while (written < b64_len) {
        size_t chunk = b64_len - written;
        if (chunk > 64)
            chunk = 64;
        memcpy(dst, b64 + written, chunk);
        dst += chunk;
        *dst++ = '\n';
        written += chunk;
    }

    memcpy(dst, footer, strlen(footer));
    dst += strlen(footer);

    *out_len = dst - *out;
    (*out)[*out_len] = '\0';
    free(b64);
    return 0;
}

int tls_init(void) {
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

int tls_config_set_cert_mem(struct tls_config* c, const uint8_t* cert, size_t len) {
    (void)cert;
    (void)len;
    set_config_error(c, "in-memory certificates are not supported");
    return -1;
}

int tls_config_set_key_mem(struct tls_config* c, const uint8_t* key, size_t len) {
    (void)key;
    (void)len;
    set_config_error(c, "in-memory keys are not supported");
    return -1;
}

int tls_config_set_verify_depth(struct tls_config* c, int verify_depth) {
    (void)c;
    (void)verify_depth;
    return 0;
}

int tls_config_set_dheparams(struct tls_config* c, const char* params) {
    (void)c;
    (void)params;
    return 0;
}

int tls_config_set_ecdhecurve(struct tls_config* c, const char* curve) {
    (void)c;
    (void)curve;
    return 0;
}

void tls_config_prefer_ciphers_client(struct tls_config* c) {
    (void)c;
}

void tls_config_prefer_ciphers_server(struct tls_config* c) {
    (void)c;
}

int tls_config_set_dgram(struct tls_config* c, int dgram) {
    c->dgram = dgram ? 1 : 0;
    return 0;
}

int tls_config_set_ocsp_staple_file(struct tls_config* c, const char* file) {
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

void tls_config_insecure_noverifytime(struct tls_config* c) {
    (void)c;
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
    if (ctx->ca_initialized) {
        mbedtls_x509_crt_free(&ctx->ca);
        ctx->ca_initialized = 0;
    }
    if (ctx->mbedtls_initialized) {
        mbedtls_ssl_free(&ctx->mssl);
        mbedtls_ssl_config_free(&ctx->mconf);
        mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
        mbedtls_entropy_free(&ctx->entropy);
        mbedtls_x509_crt_free(&ctx->cert);
        mbedtls_pk_free(&ctx->pkey);
        mbedtls_ssl_cookie_free(&ctx->cookie);
        ctx->mbedtls_initialized = 0;
    }
    free_alpn_list(ctx);
    clear_peer_cache(ctx);
    free(ctx->servername);
    free(ctx->error);
    free(ctx);
}

const char* tls_error(struct tls* ctx) {
    return ctx->error;
}

static int set_mbedtls_versions(struct tls* ctx, const struct tls_config* config) {
    uint32_t protocols = config->protocols;

    if (protocols == 0)
        protocols = TLS_PROTOCOLS_DEFAULT;

    if (config->dgram && protocols == TLS_PROTOCOLS_DEFAULT)
        protocols = TLS_PROTOCOL_TLSv1_2;

    if (protocols & (TLS_PROTOCOL_TLSv1_0 | TLS_PROTOCOL_TLSv1_1)) {
        set_config_error((struct tls_config*)config, "TLSv1.0 and TLSv1.1 are not supported by this mbedtls build");
        set_error(ctx, "TLSv1.0 and TLSv1.1 are not supported by this mbedtls build");
        return -1;
    }

    if (config->dgram && (protocols & TLS_PROTOCOL_TLSv1_3)) {
        set_config_error((struct tls_config*)config, "DTLS 1.3 is not supported");
        set_error(ctx, "DTLS 1.3 is not supported");
        return -1;
    }

    int min_ver = MBEDTLS_SSL_VERSION_TLS1_2;
    int max_ver = MBEDTLS_SSL_VERSION_TLS1_2;

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    if (protocols & TLS_PROTOCOL_TLSv1_3)
        max_ver = MBEDTLS_SSL_VERSION_TLS1_3;
#endif
    if (protocols & TLS_PROTOCOL_TLSv1_2)
        min_ver = MBEDTLS_SSL_VERSION_TLS1_2;
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    if ((protocols & TLS_PROTOCOL_TLSv1_3) && !(protocols & TLS_PROTOCOL_TLSv1_2))
        min_ver = MBEDTLS_SSL_VERSION_TLS1_3;
#endif

    mbedtls_ssl_conf_min_tls_version(&ctx->mconf, min_ver);
    mbedtls_ssl_conf_max_tls_version(&ctx->mconf, max_ver);
    return 0;
}

int tls_configure(struct tls* ctx, struct tls_config* config) {
    ctx->config = config;

    if (!psa_initialized) {
        psa_status_t status = psa_crypto_init();
        if (status != PSA_SUCCESS) {
            set_error(ctx, "psa_crypto_init failed");
            return -1;
        }
        psa_initialized = 1;
    }

    ctx->use_mbedtls_dtls = config->dgram ? 1 : 0;
    ctx->mbedtls_initialized = 1;

    mbedtls_ssl_init(&ctx->mssl);
    mbedtls_ssl_config_init(&ctx->mconf);
    mbedtls_ctr_drbg_init(&ctx->ctr_drbg);
    mbedtls_entropy_init(&ctx->entropy);
    mbedtls_x509_crt_init(&ctx->cert);
    mbedtls_pk_init(&ctx->pkey);
    mbedtls_ssl_cookie_init(&ctx->cookie);

#if defined(MBEDTLS_ENTROPY_C)
    mbedtls_entropy_add_source(&ctx->entropy, entropy_urandom, NULL, 32, MBEDTLS_ENTROPY_SOURCE_STRONG);
#endif

    const char* pers = ctx->server_mode ? "nc-srv" : "nc-cli";
    int ret = mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func, &ctx->entropy, (const unsigned char*)pers,
                                    strlen(pers));
    if (ret != 0) {
        set_error_mbedtls(ctx, ret, "mbedtls_ctr_drbg_seed failed");
        return -1;
    }

    ret = mbedtls_ssl_config_defaults(
        &ctx->mconf, ctx->server_mode ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
        ctx->use_mbedtls_dtls ? MBEDTLS_SSL_TRANSPORT_DATAGRAM : MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        set_error_mbedtls(ctx, ret, "mbedtls_ssl_config_defaults failed");
        return -1;
    }

    if (set_mbedtls_versions(ctx, config) != 0)
        return -1;

    if (ctx->server_mode) {
        if (config->verify_client || config->verify_client_optional) {
            if (load_ca_bundle(ctx, config) == -1)
                return -1;
            mbedtls_ssl_conf_ca_chain(&ctx->mconf, &ctx->ca, NULL);
            mbedtls_ssl_conf_authmode(
                &ctx->mconf, config->verify_client ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_OPTIONAL);
        }
        else {
            mbedtls_ssl_conf_authmode(&ctx->mconf, MBEDTLS_SSL_VERIFY_NONE);
        }
    }
    else {
        if (config->verify_cert) {
            if (load_ca_bundle(ctx, config) == -1)
                return -1;
            mbedtls_ssl_conf_ca_chain(&ctx->mconf, &ctx->ca, NULL);
            mbedtls_ssl_conf_authmode(&ctx->mconf, MBEDTLS_SSL_VERIFY_REQUIRED);
        }
        else {
            mbedtls_ssl_conf_authmode(&ctx->mconf, MBEDTLS_SSL_VERIFY_NONE);
        }
    }

    if (config->cert_file && config->key_file) {
        ret = mbedtls_x509_crt_parse_file(&ctx->cert, config->cert_file);
        if (ret != 0) {
            set_error_mbedtls(ctx, ret, "Failed to load certificate");
            return -1;
        }
        ret = mbedtls_pk_parse_keyfile(&ctx->pkey, config->key_file, NULL);
        if (ret != 0) {
            set_error_mbedtls(ctx, ret, "Failed to load private key");
            return -1;
        }
        ret = mbedtls_ssl_conf_own_cert(&ctx->mconf, &ctx->cert, &ctx->pkey);
        if (ret != 0) {
            set_error_mbedtls(ctx, ret, "Failed to set certificate");
            return -1;
        }
    }

    if (config->alpn) {
        if (parse_alpn_list(ctx, config->alpn) != 0) {
            set_error(ctx, "Failed to parse ALPN list");
            return -1;
        }
        if (ctx->alpn_list && ctx->alpn_count > 0) {
            ret = mbedtls_ssl_conf_alpn_protocols(&ctx->mconf, (const char* const*)ctx->alpn_list);
            if (ret != 0) {
                set_error_mbedtls(ctx, ret, "Failed to set ALPN list");
                return -1;
            }
        }
    }

    if (ctx->use_mbedtls_dtls && ctx->server_mode) {
        ret = mbedtls_ssl_cookie_setup(&ctx->cookie);
        if (ret != 0) {
            set_error_mbedtls(ctx, ret, "mbedtls_ssl_cookie_setup failed");
            return -1;
        }
        mbedtls_ssl_conf_dtls_cookies(&ctx->mconf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check, &ctx->cookie);
    }

    ret = mbedtls_ssl_setup(&ctx->mssl, &ctx->mconf);
    if (ret != 0) {
        set_error_mbedtls(ctx, ret, "mbedtls_ssl_setup failed");
        return -1;
    }

    if (ctx->use_mbedtls_dtls)
        mbedtls_ssl_set_timer_cb(&ctx->mssl, &ctx->timer, mbedtls_timing_set_delay, mbedtls_timing_get_delay);

    return 0;
}

void tls_reset(struct tls* ctx) {
    if (!ctx)
        return;
    if (ctx->mbedtls_initialized)
        mbedtls_ssl_session_reset(&ctx->mssl);
    ctx->handshake_complete = 0;
    clear_peer_cache(ctx);
}

int tls_connect_socket(struct tls* ctx, int s, const char* servername) {
    ctx->socket = s;
    mbedtls_ssl_set_bio(&ctx->mssl, &ctx->socket, stream_send, stream_recv, NULL);

    if (servername) {
        free(ctx->servername);
        ctx->servername = strdup(servername);
        int ret = mbedtls_ssl_set_hostname(&ctx->mssl, servername);
        if (ret != 0) {
            set_error_mbedtls(ctx, ret, "mbedtls_ssl_set_hostname failed");
            return -1;
        }
    }

    return 0;
}

int tls_accept_socket(struct tls* ctx, struct tls** cctx, int s) {
    struct tls* new_ctx = tls_server();
    if (!new_ctx)
        return -1;

    new_ctx->socket = s;
    if (tls_configure(new_ctx, ctx->config) == -1) {
        tls_free(new_ctx);
        return -1;
    }

    mbedtls_ssl_set_bio(&new_ctx->mssl, &new_ctx->socket, stream_send, stream_recv, NULL);

    if (ctx->config && ctx->config->dgram && ctx->server_mode) {
        struct sockaddr_storage peer;
        socklen_t peer_len = sizeof(peer);
        if (getpeername(s, (struct sockaddr*)&peer, &peer_len) == 0)
            mbedtls_ssl_set_client_transport_id(&new_ctx->mssl, (const unsigned char*)&peer, peer_len);
    }

    *cctx = new_ctx;
    return 0;
}

int tls_handshake(struct tls* ctx) {
    int ret = mbedtls_ssl_handshake(&ctx->mssl);
    if (ret == 0) {
        ctx->handshake_complete = 1;
        return 0;
    }
    if (ret == MBEDTLS_ERR_SSL_WANT_READ)
        return TLS_WANT_POLLIN;
    if (ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        return TLS_WANT_POLLOUT;
    if (ctx->use_mbedtls_dtls && (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED || ret == MBEDTLS_ERR_SSL_TIMEOUT))
        return TLS_WANT_POLLOUT;
    set_error_mbedtls(ctx, ret, "TLS handshake failed");
    return -1;
}

ssize_t tls_read(struct tls* ctx, void* buf, size_t buflen) {
    int ret = mbedtls_ssl_read(&ctx->mssl, buf, buflen);
    if (ret > 0)
        return ret;
    if (ret == 0)
        return 0;
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_TIMEOUT)
        return TLS_WANT_POLLIN;
    if (ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        return TLS_WANT_POLLOUT;
    set_error_mbedtls(ctx, ret, "TLS read failed");
    return -1;
}

ssize_t tls_write(struct tls* ctx, const void* buf, size_t buflen) {
    int ret = mbedtls_ssl_write(&ctx->mssl, buf, buflen);
    if (ret > 0)
        return ret;
    if (ret == MBEDTLS_ERR_SSL_WANT_READ)
        return TLS_WANT_POLLIN;
    if (ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        return TLS_WANT_POLLOUT;
    set_error_mbedtls(ctx, ret, "TLS write failed");
    return -1;
}

int tls_close(struct tls* ctx) {
    if (!ctx)
        return 0;
    int ret;
    do {
        ret = mbedtls_ssl_close_notify(&ctx->mssl);
    } while (ret == MBEDTLS_ERR_SSL_WANT_WRITE || ret == MBEDTLS_ERR_SSL_WANT_READ);
    return 0;
}

int tls_peer_cert_provided(struct tls* ctx) {
    return mbedtls_ssl_get_peer_cert(&ctx->mssl) != NULL;
}

static const mbedtls_x509_crt* get_peer_cert(struct tls* ctx) {
    return mbedtls_ssl_get_peer_cert(&ctx->mssl);
}

const char* tls_peer_cert_hash(struct tls* ctx) {
    const mbedtls_x509_crt* cert = get_peer_cert(ctx);
    if (!cert)
        return NULL;
    if (ctx->peer_cert_hash)
        return ctx->peer_cert_hash;

    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md)
        return NULL;
    if (mbedtls_md(md, cert->raw.p, cert->raw.len, hash) != 0)
        return NULL;

    ctx->peer_cert_hash = calloc(1, 65);
    if (!ctx->peer_cert_hash)
        return NULL;

    for (size_t i = 0; i < 32; i++)
        snprintf(&ctx->peer_cert_hash[i * 2], 3, "%02x", hash[i]);

    return ctx->peer_cert_hash;
}

const char* tls_peer_cert_subject(struct tls* ctx) {
    const mbedtls_x509_crt* cert = get_peer_cert(ctx);
    if (!cert)
        return NULL;
    if (ctx->peer_cert_subject)
        return ctx->peer_cert_subject;

    char buf[1024];
    mbedtls_x509_dn_gets(buf, sizeof(buf), &cert->subject);
    ctx->peer_cert_subject = strdup(buf);
    return ctx->peer_cert_subject;
}

const char* tls_peer_cert_issuer(struct tls* ctx) {
    const mbedtls_x509_crt* cert = get_peer_cert(ctx);
    if (!cert)
        return NULL;
    if (ctx->peer_cert_issuer)
        return ctx->peer_cert_issuer;

    char buf[1024];
    mbedtls_x509_dn_gets(buf, sizeof(buf), &cert->issuer);
    ctx->peer_cert_issuer = strdup(buf);
    return ctx->peer_cert_issuer;
}

int tls_peer_cert_contains_name(struct tls* ctx, const char* name) {
    const mbedtls_x509_crt* cert = get_peer_cert(ctx);
    if (!cert || !name)
        return 0;
    if (!ctx->ca_initialized)
        return 0;

    uint32_t flags = 0;
    int ret = mbedtls_x509_crt_verify((mbedtls_x509_crt*)cert, &ctx->ca, NULL, name, &flags, NULL, NULL);
    if (ret == 0)
        return 1;
    if (flags == (uint32_t)-1)
        return 0;
    return (flags & MBEDTLS_X509_BADCERT_CN_MISMATCH) == 0;
}

const char* tls_conn_version(struct tls* ctx) {
    return mbedtls_ssl_get_version(&ctx->mssl);
}

const char* tls_conn_cipher(struct tls* ctx) {
    return mbedtls_ssl_get_ciphersuite(&ctx->mssl);
}

const char* tls_conn_alpn_selected(struct tls* ctx) {
    return mbedtls_ssl_get_alpn_protocol(&ctx->mssl);
}

const char* tls_conn_servername(struct tls* ctx) {
    const char* sni = mbedtls_ssl_get_hostname(&ctx->mssl);
    return sni ? sni : ctx->servername;
}

const char* tls_default_ca_cert_file(void) {
    return NULL;
}

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

static time_t x509_time_to_time_t(const mbedtls_x509_time* t) {
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    tm.tm_year = t->year - 1900;
    tm.tm_mon = t->mon - 1;
    tm.tm_mday = t->day;
    tm.tm_hour = t->hour;
    tm.tm_min = t->min;
    tm.tm_sec = t->sec;
#if defined(_GNU_SOURCE)
    return timegm(&tm);
#else
    return mktime(&tm);
#endif
}

time_t tls_peer_cert_notbefore(struct tls* ctx) {
    const mbedtls_x509_crt* cert = get_peer_cert(ctx);
    if (!cert)
        return (time_t)-1;
    return x509_time_to_time_t(&cert->valid_from);
}

time_t tls_peer_cert_notafter(struct tls* ctx) {
    const mbedtls_x509_crt* cert = get_peer_cert(ctx);
    if (!cert)
        return (time_t)-1;
    return x509_time_to_time_t(&cert->valid_to);
}

const uint8_t* tls_peer_cert_chain_pem(struct tls* ctx, size_t* len) {
    if (ctx->peer_chain_pem) {
        if (len)
            *len = ctx->peer_chain_pem_len;
        return ctx->peer_chain_pem;
    }

    const mbedtls_x509_crt* cert = get_peer_cert(ctx);
    if (!cert)
        return NULL;

    unsigned char* out = NULL;
    size_t out_len = 0;

    for (const mbedtls_x509_crt* cur = cert; cur; cur = cur->next) {
        if (append_pem_cert(&out, &out_len, cur->raw.p, cur->raw.len) != 0) {
            free(out);
            return NULL;
        }
    }

    ctx->peer_chain_pem = out;
    ctx->peer_chain_pem_len = out_len;
    if (len)
        *len = out_len;
    return ctx->peer_chain_pem;
}

uint8_t* tls_load_file(const char* file, size_t* len, char* password) {
    (void)password;
    if (len)
        *len = 0;

    FILE* fp = fopen(file, "rb");
    if (!fp)
        return NULL;
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    long sz = ftell(fp);
    if (sz < 0) {
        fclose(fp);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }
    uint8_t* buf = calloc(1, (size_t)sz + 1);
    if (!buf) {
        fclose(fp);
        return NULL;
    }
    size_t n = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    if (n != (size_t)sz) {
        free(buf);
        return NULL;
    }
    if (len)
        *len = (size_t)sz;
    return buf;
}

void tls_unload_file(uint8_t* buf, size_t len) {
    if (!buf)
        return;
    memset(buf, 0, len);
    free(buf);
}
