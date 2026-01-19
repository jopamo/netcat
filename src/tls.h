#ifndef TLS_H
#define TLS_H

#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

struct tls;
struct tls_config;

#define TLS_API 20200120

#define TLS_PROTOCOL_TLSv1_0 (1 << 1)
#define TLS_PROTOCOL_TLSv1_1 (1 << 2)
#define TLS_PROTOCOL_TLSv1_2 (1 << 3)
#define TLS_PROTOCOL_TLSv1_3 (1 << 4)

#define TLS_PROTOCOLS_ALL TLS_PROTOCOL_TLSv1_0 | TLS_PROTOCOL_TLSv1_1 | TLS_PROTOCOL_TLSv1_2 | TLS_PROTOCOL_TLSv1_3
#define TLS_PROTOCOLS_DEFAULT (TLS_PROTOCOL_TLSv1_2 | TLS_PROTOCOL_TLSv1_3)

#define TLS_WANT_POLLIN -2
#define TLS_WANT_POLLOUT -3

#define TLS_OCSP_RESPONSE_SUCCESSFUL 0

/*
 * Flags for tls_config_set_verify_client_optional()
 */
/*
 * Flags for tls_config_set_dheparams()
 */
#define TLS_MAX_SESSION_ID_LENGTH 32
#define TLS_TICKET_KEY_SIZE 48

int tls_init(void);

struct tls_config* tls_config_new(void);
void tls_config_free(struct tls_config* _config);
const char* tls_config_error(struct tls_config* _config);

int tls_config_set_ca_file(struct tls_config* _config, const char* _ca_file);
int tls_config_set_ca_path(struct tls_config* _config, const char* _ca_path);
int tls_config_set_cert_file(struct tls_config* _config, const char* _cert_file);
int tls_config_set_cert_mem(struct tls_config* _config, const uint8_t* _cert, size_t _len);
int tls_config_set_ciphers(struct tls_config* _config, const char* _ciphers);
int tls_config_set_dheparams(struct tls_config* _config, const char* _params);
int tls_config_set_ecdhecurve(struct tls_config* _config, const char* _curve);
int tls_config_set_key_file(struct tls_config* _config, const char* _key_file);
int tls_config_set_key_mem(struct tls_config* _config, const uint8_t* _key, size_t _len);
int tls_config_set_protocols(struct tls_config* _config, uint32_t _protocols);
int tls_config_set_verify_depth(struct tls_config* _config, int _verify_depth);
int tls_config_set_alpn(struct tls_config* _config, const char* _alpn);
int tls_config_set_dgram(struct tls_config* _config, int _dgram);
int tls_config_set_ktls(struct tls_config* _config, int _ktls);
int tls_config_set_ocsp_staple_file(struct tls_config* _config, const char* _file);

void tls_config_prefer_ciphers_client(struct tls_config* _config);
void tls_config_prefer_ciphers_server(struct tls_config* _config);

void tls_config_insecure_noverifycert(struct tls_config* _config);
void tls_config_insecure_noverifyname(struct tls_config* _config);
void tls_config_insecure_noverifytime(struct tls_config* _config);
void tls_config_verify_client(struct tls_config* _config);
void tls_config_verify_client_optional(struct tls_config* _config);
void tls_config_ocsp_require_stapling(struct tls_config* _config);

int tls_config_parse_protocols(uint32_t* _protocols, const char* _protostr);

struct tls* tls_client(void);
struct tls* tls_server(void);
int tls_configure(struct tls* _ctx, struct tls_config* _config);
void tls_reset(struct tls* _ctx);
void tls_free(struct tls* _ctx);

int tls_accept_socket(struct tls* _ctx, struct tls** _cctx, int _socket);
int tls_connect_socket(struct tls* _ctx, int _s, const char* _servername);
int tls_handshake(struct tls* _ctx);
ssize_t tls_read(struct tls* _ctx, void* _buf, size_t _buflen);
ssize_t tls_write(struct tls* _ctx, const void* _buf, size_t _buflen);
int tls_close(struct tls* _ctx);

const char* tls_error(struct tls* _ctx);

int tls_peer_cert_provided(struct tls* _ctx);
int tls_peer_cert_contains_name(struct tls* _ctx, const char* _name);
const char* tls_peer_cert_hash(struct tls* _ctx);
const char* tls_peer_cert_issuer(struct tls* _ctx);
const char* tls_peer_cert_subject(struct tls* _ctx);
time_t tls_peer_cert_notbefore(struct tls* _ctx);
time_t tls_peer_cert_notafter(struct tls* _ctx);
const uint8_t* tls_peer_cert_chain_pem(struct tls* _ctx, size_t* _len);

const char* tls_conn_version(struct tls* _ctx);
const char* tls_conn_cipher(struct tls* _ctx);
const char* tls_conn_alpn_selected(struct tls* _ctx);
const char* tls_conn_servername(struct tls* _ctx);

const char* tls_peer_ocsp_url(struct tls* _ctx);
int tls_peer_ocsp_response_status(struct tls* _ctx);
const char* tls_peer_ocsp_result(struct tls* _ctx);
int tls_peer_ocsp_cert_status(struct tls* _ctx);
int tls_peer_ocsp_crl_reason(struct tls* _ctx);
time_t tls_peer_ocsp_this_update(struct tls* _ctx);
time_t tls_peer_ocsp_next_update(struct tls* _ctx);
time_t tls_peer_ocsp_revocation_time(struct tls* _ctx);

uint8_t* tls_load_file(const char* _file, size_t* _len, char* _password);
void tls_unload_file(uint8_t* _buf, size_t _len);

/* Helper functions often available in libtls */
const char* tls_default_ca_cert_file(void);

#endif /* TLS_H */
