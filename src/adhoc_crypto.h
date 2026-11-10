// The native library adhoc-crypto, plain C calls. What they mean, the memory of a chain and of a handshake of Noise: PORTING.md, README.md.
// Load it at run time: libadhoc-crypto-<version>.<dll|so|dylib>; adhoc_abi() says whether it is the one this code expects.
#ifndef ADHOC_CRYPTO_H
#define ADHOC_CRYPTO_H
#include <stdint.h>
#ifdef _WIN32
#define ADHOC_API int32_t adhoc_abi(void);
ADHOC_API int32_t adhoc_aead_size(void);
ADHOC_API int32_t adhoc_aead_init(int32_t kind, void *ctx, const uint8_t *key, int32_t key_len);
ADHOC_API int32_t adhoc_seal(int64_t ctx, int64_t n, int64_t ad, int32_t ad_len, int64_t text, int32_t len);
ADHOC_API int32_t adhoc_open(int64_t ctx, int64_t n, int64_t ad, int32_t ad_len, int64_t text, int32_t len);
ADHOC_API int32_t adhoc_seal_nonce(int64_t ctx, const uint8_t *nonce, const uint8_t *ad, int32_t ad_len, uint8_t *text, int32_t len);
ADHOC_API int32_t adhoc_open_nonce(int64_t ctx, const uint8_t *nonce, const uint8_t *ad, int32_t ad_len, uint8_t *text, int32_t len);
ADHOC_API int64_t adhoc_seal_records(int64_t ctx, int64_t n, int64_t address, int32_t bytes);
ADHOC_API int64_t adhoc_open_records(int64_t ctx, int64_t n, int64_t address, int32_t have, int32_t max);
ADHOC_API int32_t adhoc_stream_size(void);
ADHOC_API void adhoc_stream_xor(int64_t state, int64_t address, int32_t len);
ADHOC_API int32_t adhoc_x25519(uint8_t *shared, const uint8_t *secret, const uint8_t *peer);
ADHOC_API void adhoc_x25519_public(uint8_t *pub, const uint8_t *secret);
ADHOC_API void adhoc_x25519_keypair(uint8_t *secret, uint8_t *pub);
ADHOC_API int32_t adhoc_noise_size(void);
ADHOC_API int32_t adhoc_noise_tx(void);
ADHOC_API int32_t adhoc_noise_rx(void);
ADHOC_API void adhoc_noise_init(int64_t state, int32_t pattern, int32_t initiator, const uint8_t *prologue, int32_t prologue_len, const uint8_t *static_secret, const uint8_t *static_public, const uint8_t *peer, const uint8_t *ephemeral);
ADHOC_API int32_t adhoc_noise_write(int64_t state, uint8_t *dst, int32_t cap, const uint8_t *payload, int32_t len);
ADHOC_API int32_t adhoc_noise_read(int64_t state, const uint8_t *msg, int32_t len, uint8_t *payload, int32_t room);
ADHOC_API int64_t adhoc_tls_context(void);
ADHOC_API int64_t adhoc_tls_server_context(const void *chain, int32_t chain_len, const void *key, int32_t key_len);
ADHOC_API void adhoc_tls_context_free(int64_t ctx);
ADHOC_API int64_t adhoc_tls_server(int64_t ctx);
ADHOC_API int64_t adhoc_tls_client(int64_t ctx, const char *host, const uint8_t *alpn, int32_t alpn_len, int (*verify)(void *, int, const uint8_t **, const int *), void *verify_ctx);
ADHOC_API int64_t adhoc_tls_handshake(int64_t conn, int64_t in, int32_t in_len, int64_t out, int32_t out_cap);
ADHOC_API void adhoc_tls_tx_limit(int64_t conn, int64_t records);
ADHOC_API int32_t adhoc_tls_control(int64_t conn, int64_t record);
ADHOC_API void adhoc_tls_close_notify(int64_t conn);
ADHOC_API const char * adhoc_tls_error(int64_t conn);
ADHOC_API void adhoc_tls_free(int64_t conn);
ADHOC_API int32_t adhoc_chain_size(void);
ADHOC_API int32_t adhoc_chain_tx(int64_t chain);
ADHOC_API int64_t adhoc_chain_rx(int64_t chain, uint8_t *base, int32_t at, int32_t limit);
ADHOC_API void adhoc_ed25519_keypair(uint8_t *secret, uint8_t *pub, const uint8_t *seed);
ADHOC_API int32_t adhoc_ed25519_sign(uint8_t *signature, const uint8_t *secret, const uint8_t *message, int64_t len);
ADHOC_API int32_t adhoc_ed25519_verify(const uint8_t *signature, const uint8_t *pub, const uint8_t *message, int64_t len);
ADHOC_API int32_t adhoc_pair_key(uint8_t *key, uint8_t *iv, int32_t *id, const uint8_t *secret, const uint8_t *their, const uint8_t *label, int32_t label_len);
ADHOC_API int32_t adhoc_pack_seal(int64_t ctx, int64_t n, int64_t secret, int64_t address, int32_t header, int32_t len);
ADHOC_API int32_t adhoc_pack_open(int64_t ctx, int64_t n, int64_t pub, int64_t address, int32_t header, int32_t total);
ADHOC_API int32_t adhoc_stages_size(void);
ADHOC_API int32_t adhoc_stages_tx(int64_t stages, uint8_t *out, int32_t room, int32_t end);
ADHOC_API int32_t adhoc_stages_rx(int64_t stages, uint8_t *in, int32_t len, int32_t end);
ADHOC_API void adhoc_stages_xor(int64_t stages, uint8_t *p, int32_t len);
ADHOC_API int32_t adhoc_stages_room(int64_t stages, int32_t need);
ADHOC_API void adhoc_stages_free(int64_t stages);
#ifdef __cplusplus
}
#endif
#endif
