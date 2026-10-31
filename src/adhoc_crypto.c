// A TLS 1.3 client over BoringSSL: the handshake is BoringSSL's and is freed when it ends; every record after that is
// sealed and opened in place, in the caller's direct buffer, in one JNI call and with no allocation.
#include <jni.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/aead.h>
#include <openssl/bio.h>
#include <openssl/chacha.h>
#include <openssl/curve25519.h>
#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>
#include <openssl/pem.h>
#include <openssl/poly1305.h>
#include <openssl/pool.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509.h>

enum { HEADER = 5, TAG = 16, MAX_DATA = 16384, MAX_CIPHERTEXT = 16384 + 256 };
enum { APPLICATION_DATA = 23, HANDSHAKE = 22, ALERT = 21 };
enum { NEW_SESSION_TICKET = 4, KEY_UPDATE = 24 };
enum { CLOSE_NOTIFY = 0, UNEXPECTED_MESSAGE = 10, BAD_RECORD_MAC = 20, RECORD_OVERFLOW = 22, ILLEGAL_PARAMETER = 47, DECODE_ERROR = 50, USER_CANCELED = 90 };
enum { DONE = 0, NEED_READ = 1, FAILED = 2 };
// What goes back in one jlong with the size: the Java side asks nothing else on the path of a record.
#define NEEDS_CONTROL (1 << 16)
#define PEER_CLOSED (1 << 17)

typedef struct
{
    EVP_AEAD_CTX *tx, *rx;
    const EVP_AEAD *aead;
    const EVP_MD *md;
    uint64_t tx_seq, rx_seq, tx_limit;
    uint8_t tx_iv[12], rx_iv[12];
    int server;
    uint8_t tx_secret[EVP_MAX_MD_SIZE], rx_secret[EVP_MAX_MD_SIZE];
    size_t key_len, secret_len;
    int pending_alert, pending_key_update, closed, verified, tx_updates, rx_updates, cipher;
    uint8_t *partial; // a handshake message that spans records, only while it does
    size_t partial_len;
    const char *error;
    char detail[256];
    // only while the handshake runs
    SSL *ssl;
    BIO *rbio, *wbio;
    char *host;
    JNIEnv *env;
    jobject owner;
    int (*verify_fn)(void *ctx, int count, const uint8_t **der, const int *len); // a runtime other than Java checks the chain here: 1 - trusted
    void *verify_ctx;
    uint16_t group;
} Conn;

static int ex_index = -1;

static const char *fatal(Conn *c, int alert, const char *what)
{
    c->pending_alert = alert;
    c->pending_key_update = 0;
    c->error = what;
    ERR_clear_error();
    return what;
}

static void note(Conn *c, const char *prefix)
{
    char text[200];
    ERR_error_string_n(ERR_get_error(), text, sizeof text);
    ERR_clear_error();
    size_t n = strlen(prefix), m = strlen(text);
    if (n + m + 3 > sizeof c->detail)
        m = sizeof c->detail - n - 3;
    memcpy(c->detail, prefix, n);
    c->detail[n] = ':', c->detail[n + 1] = ' ';
    memcpy(c->detail + n + 2, text, m);
    c->detail[n + 2 + m] = 0;
    c->error = c->detail;
}

//#region the key schedule
static int expand(Conn *c, const uint8_t *secret, const char *label, uint8_t *out, size_t len)
{
    uint8_t info[64];
    size_t n = strlen(label), at = 0;
    info[at++] = 0, info[at++] = (uint8_t)len, info[at++] = (uint8_t)(6 + n);
    memcpy(info + at, "tls13 ", 6), at += 6;
    memcpy(info + at, label, n), at += n;
    info[at++] = 0;
    return HKDF_expand(out, len, c->md, secret, c->secret_len, info, at);
}

static int install(Conn *c, const uint8_t *secret, EVP_AEAD_CTX **ctx, uint8_t *iv, uint64_t *seq)
{
    uint8_t key[32];
    if (!expand(c, secret, "key", key, c->key_len) || !expand(c, secret, "iv", iv, 12))
        return 0;
    if (*ctx)
        EVP_AEAD_CTX_free(*ctx);
    *ctx = EVP_AEAD_CTX_new(c->aead, key, c->key_len, TAG);
    OPENSSL_cleanse(key, sizeof key);
    *seq = 0;
    return *ctx != NULL;
}

static int next_secret(Conn *c, uint8_t *secret)
{
    uint8_t out[EVP_MAX_MD_SIZE];
    if (!expand(c, secret, "traffic upd", out, c->secret_len))
        return 0;
    memcpy(secret, out, c->secret_len);
    OPENSSL_cleanse(out, sizeof out);
    return 1;
}

static int schedule(Conn *c, int cipher)
{
    c->cipher = cipher;
    switch (cipher)
    {
        case 0x1301: c->aead = EVP_aead_aes_128_gcm(), c->md = EVP_sha256(), c->key_len = 16, c->secret_len = 32; break;
        case 0x1302: c->aead = EVP_aead_aes_256_gcm(), c->md = EVP_sha384(), c->key_len = 32, c->secret_len = 48; break;
        case 0x1303: c->aead = EVP_aead_chacha20_poly1305(), c->md = EVP_sha256(), c->key_len = 32, c->secret_len = 32; break;
        default: return 0;
    }
    return install(c, c->tx_secret, &c->tx, c->tx_iv, &c->tx_seq) && install(c, c->rx_secret, &c->rx, c->rx_iv, &c->rx_seq);
}
//#endregion

//#region records
static inline void nonce(uint8_t out[12], const uint8_t iv[12], uint64_t seq)
{
    memcpy(out, iv, 4);
    for (int i = 0; i < 8; i++)
        out[4 + i] = iv[4 + i] ^ (uint8_t)(seq >> (56 - 8 * i));
}

static inline int seal(Conn *c, uint8_t *rec, size_t len, int type, size_t padding)
{
    uint8_t iv[12], *body = rec + HEADER;
    const size_t inner = len + 1 + padding, ciphertext = inner + TAG;
    size_t tag_len = 0;
    rec[0] = APPLICATION_DATA, rec[1] = 3, rec[2] = 3, rec[3] = (uint8_t)(ciphertext >> 8), rec[4] = (uint8_t)ciphertext;
    body[len] = (uint8_t)type;
    if (padding)
        memset(body + len + 1, 0, padding);
    nonce(iv, c->tx_iv, c->tx_seq);
    if (!EVP_AEAD_CTX_seal_scatter(c->tx, body, body + inner, &tag_len, TAG, iv, 12, body, inner, NULL, 0, rec, HEADER))
        return -1;
    if (c->tx_limit <= ++c->tx_seq)
        c->pending_key_update = 1;
    return (int)(HEADER + ciphertext);
}

static int handshake_messages(Conn *c, const uint8_t *p, size_t len)
{
    size_t from = 0;
    int update = 0;
    while (len - from >= 4)
    {
        const int type = p[from];
        const size_t size = (size_t)p[from + 1] << 16 | (size_t)p[from + 2] << 8 | p[from + 3];
        if (size > 65536 - 4)
            return fatal(c, UNEXPECTED_MESSAGE, "too long a handshake message"), -1;
        if (len - from - 4 < size)
            break;
        if (type == KEY_UPDATE)
        {
            if (size != 1)
                return fatal(c, DECODE_ERROR, "a KeyUpdate of a wrong size"), -1;
            if (p[from + 4] > 1)
                return fatal(c, ILLEGAL_PARAMETER, "a KeyUpdate asking the unknown"), -1;
            if (p[from + 4] == 1)
                c->pending_key_update = 1;
            update = 1;
        }
        else if (type != NEW_SESSION_TICKET) // no resumption here: tickets are dropped as they come
            return fatal(c, UNEXPECTED_MESSAGE, "an unexpected handshake message"), -1;
        from += 4 + size;
    }
    const size_t rest = len - from;
    if (update && rest != 0) // RFC 8446 5.1: a key change ends its record
        return fatal(c, UNEXPECTED_MESSAGE, "data after a KeyUpdate in its record"), -1;
    if (rest != 0)
    {
        uint8_t *held = (uint8_t *)malloc(rest);
        if (!held)
            return fatal(c, 80, "out of memory"), -1;
        memcpy(held, p + from, rest);
        free(c->partial);
        c->partial = held;
    }
    else
    {
        free(c->partial);
        c->partial = NULL;
    }
    c->partial_len = rest;
    if (update)
    {
        if (!next_secret(c, c->rx_secret) || !install(c, c->rx_secret, &c->rx, c->rx_iv, &c->rx_seq))
            return fatal(c, 80, "the key update"), -1;
        c->rx_updates++;
    }
    return 0;
}

static int handshake_record(Conn *c, const uint8_t *p, size_t len)
{
    if (len == 0)
        return fatal(c, UNEXPECTED_MESSAGE, "an empty handshake record"), -1;
    if (c->partial == NULL)
        return handshake_messages(c, p, len);
    if (c->partial_len + len > 65536)
        return fatal(c, UNEXPECTED_MESSAGE, "too long a handshake message"), -1;
    uint8_t *joined = (uint8_t *)malloc(c->partial_len + len);
    if (!joined)
        return fatal(c, 80, "out of memory"), -1;
    memcpy(joined, c->partial, c->partial_len);
    memcpy(joined + c->partial_len, p, len);
    const int ret = handshake_messages(c, joined, c->partial_len + len);
    free(joined);
    return ret;
}

static int alert_record(Conn *c, const uint8_t *p, size_t len)
{
    if (len != 2)
        return fatal(c, DECODE_ERROR, "an alert of a wrong size"), -1;
    if (p[1] == CLOSE_NOTIFY)
        c->closed = 1;
    else if (p[1] != USER_CANCELED)
    {
        snprintf(c->detail, sizeof c->detail, "the peer's alert %d", p[1]);
        c->error = c->detail;
        c->pending_alert = -1;
        return -1;
    }
    return 0;
}

// >0: consumed << 32 | flags | bytes of data at rec + HEADER; 0: not all here; -1: over.
static inline jlong open_record(Conn *c, uint8_t *rec, size_t have)
{
    if (c->closed)
        return c->error = "past close_notify", -1;
    if (have < HEADER)
        return 0;
    const size_t ciphertext = (size_t)rec[3] << 8 | rec[4];
    if (rec[0] != APPLICATION_DATA)
        return fatal(c, UNEXPECTED_MESSAGE, "a record of an unexpected type"), -1;
    if (ciphertext > MAX_CIPHERTEXT)
        return fatal(c, RECORD_OVERFLOW, "too long a record"), -1;
    if (ciphertext <= TAG)
        return fatal(c, DECODE_ERROR, "too short a record"), -1;
    const size_t total = HEADER + ciphertext;
    if (have < total)
        return 0;
    uint8_t iv[12], *body = rec + HEADER;
    const size_t inner = ciphertext - TAG;
    nonce(iv, c->rx_iv, c->rx_seq);
    if (!EVP_AEAD_CTX_open_gather(c->rx, body, iv, 12, body, inner, body + inner, TAG, rec, HEADER))
        return fatal(c, BAD_RECORD_MAC, "the record does not authenticate"), -1;
    c->rx_seq++;
    size_t n = inner;
    while (n > 0 && body[n - 1] == 0)
        n--;
    if (n == 0)
        return fatal(c, UNEXPECTED_MESSAGE, "a record with no type"), -1;
    const int type = body[--n];
    if (n > MAX_DATA)
        return fatal(c, RECORD_OVERFLOW, "too much content in a record"), -1;
    size_t data = 0;
    if (type == APPLICATION_DATA)
        data = n;
    else if (type == HANDSHAKE)
    {
        if (handshake_record(c, body, n) != 0)
            return -1;
    }
    else if (type == ALERT)
    {
        if (alert_record(c, body, n) != 0)
            return -1;
    }
    else
        return fatal(c, UNEXPECTED_MESSAGE, "an unknown content type"), -1;
    return (jlong)total << 32 | (jlong)data | (c->pending_key_update || c->pending_alert >= 0 ? NEEDS_CONTROL : 0) | (c->closed ? PEER_CLOSED : 0);
}
//#endregion

//#region the handshake
static int is_ip(const char *host)
{
    if (strchr(host, ':'))
        return 1;
    for (; *host; host++)
        if (*host != '.' && (*host < '0' || *host > '9'))
            return 0;
    return 1;
}

static enum ssl_verify_result_t verify_cb(SSL *ssl, uint8_t *out_alert)
{
    Conn *c = (Conn *)SSL_get_ex_data(ssl, ex_index);
    const STACK_OF(CRYPTO_BUFFER) *chain = SSL_get0_peer_certificates(ssl);
    const size_t n = chain ? sk_CRYPTO_BUFFER_num(chain) : 0;
    if (n == 0)
        return c->error = "no certificate", ssl_verify_invalid;
    if (c->verify_fn)
    {
        const uint8_t *der[16];
        int len[16];
        const int count = n < 16 ? (int)n : 16;
        for (int i = 0; i < count; i++)
        {
            der[i] = CRYPTO_BUFFER_data(sk_CRYPTO_BUFFER_value(chain, (size_t)i));
            len[i] = (int)CRYPTO_BUFFER_len(sk_CRYPTO_BUFFER_value(chain, (size_t)i));
        }
        if (c->verify_fn(c->verify_ctx, count, der, len) != 1)
            return c->error = "the certificate is not trusted", ssl_verify_invalid;
    }
    else if (!c->env)
        return c->error = "nothing to check the certificate with", ssl_verify_invalid;
    else
    {
    JNIEnv *env = c->env;
    jclass bytes = (*env)->FindClass(env, "[B");
    jobjectArray certs = bytes ? (*env)->NewObjectArray(env, (jsize)n, bytes, NULL) : NULL;
    if (!certs)
    {
        (*env)->ExceptionClear(env);
        return c->error = "out of memory", ssl_verify_invalid;
    }
    for (size_t i = 0; i < n; i++)
    {
        const CRYPTO_BUFFER *b = sk_CRYPTO_BUFFER_value(chain, i);
        jbyteArray der = (*env)->NewByteArray(env, (jsize)CRYPTO_BUFFER_len(b));
        if (!der)
        {
            (*env)->ExceptionClear(env);
            return c->error = "out of memory", ssl_verify_invalid;
        }
        (*env)->SetByteArrayRegion(env, der, 0, (jsize)CRYPTO_BUFFER_len(b), (const jbyte *)CRYPTO_BUFFER_data(b));
        (*env)->SetObjectArrayElement(env, certs, (jsize)i, der);
        (*env)->DeleteLocalRef(env, der);
    }
    jmethodID verify = (*env)->GetMethodID(env, (*env)->GetObjectClass(env, c->owner), "verify", "([[B)Z");
    const jboolean trusted = verify ? (*env)->CallBooleanMethod(env, c->owner, verify, certs) : JNI_FALSE;
    if ((*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionClear(env);
        return c->error = "the certificate check threw", ssl_verify_invalid;
    }
    if (!trusted)
        return c->error = "the certificate is not trusted", ssl_verify_invalid;
    }

    const CRYPTO_BUFFER *leaf = sk_CRYPTO_BUFFER_value(chain, 0);
    const uint8_t *der = CRYPTO_BUFFER_data(leaf);
    X509 *x509 = d2i_X509(NULL, &der, (long)CRYPTO_BUFFER_len(leaf));
    if (!x509)
        return c->error = "the certificate does not parse", ssl_verify_invalid;
    const int ok = is_ip(c->host) ? X509_check_ip_asc(x509, c->host, 0) : X509_check_host(x509, c->host, strlen(c->host), 0, NULL);
    X509_free(x509);
    if (ok != 1)
    {
        *out_alert = SSL_AD_BAD_CERTIFICATE;
        return c->error = "the certificate is not of this host", ssl_verify_invalid;
    }
    c->verified = 1;
    return ssl_verify_ok;
}

static int hex(char ch) { return ch >= '0' && ch <= '9' ? ch - '0' : ch >= 'a' && ch <= 'f' ? ch - 'a' + 10 : ch >= 'A' && ch <= 'F' ? ch - 'A' + 10 : -1; }

// LABEL <client random> <secret>. The secrets stop here, they never reach Java.
static void keylog_cb(const SSL *ssl, const char *line)
{
    Conn *c = (Conn *)SSL_get_ex_data(ssl, ex_index);
    const int client = strncmp(line, "CLIENT_TRAFFIC_SECRET_0 ", 24) == 0, server = strncmp(line, "SERVER_TRAFFIC_SECRET_0 ", 24) == 0;
    uint8_t *to = !client && !server ? NULL : client != c->server ? c->tx_secret : c->rx_secret; // the client's secret is what a client sends under
    if (!to)
        return;
    const char *p = strchr(line + 24, ' ');
    if (!p)
        return;
    p++;
    for (size_t i = 0; i < EVP_MAX_MD_SIZE && hex(p[0]) >= 0 && hex(p[1]) >= 0; i++, p += 2)
        to[i] = (uint8_t)(hex(p[0]) << 4 | hex(p[1]));
}

static void release_handshake(Conn *c)
{
    if (c->ssl)
    {
        SSL_free(c->ssl); // with its BIOs
        c->ssl = NULL;
        c->rbio = c->wbio = NULL;
    }
    free(c->host);
    c->host = NULL;
}

static int finish_handshake(Conn *c)
{
    if (!c->verified)
        return c->error = "the handshake ended with no verification", 0;
    const int id = SSL_CIPHER_get_protocol_id(SSL_get_current_cipher(c->ssl));
    c->group = SSL_get_group_id(c->ssl);
    if (!schedule(c, id))
        return note(c, "the key schedule"), 0;
    release_handshake(c);
    return 1;
}
//#endregion

//#region JNI
#define FN(ret, name) JNIEXPORT ret JNICALL Java_org_unirail_crypto_Tls13_##name

FN(jlong, newContext)(JNIEnv *env, jclass cls)
{
    if (ex_index < 0)
        ex_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    if (!ctx || !SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) || !SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION))
        return 0;
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_grease_enabled(ctx, 1);
    SSL_CTX_set_custom_verify(ctx, SSL_VERIFY_PEER, verify_cb);
    SSL_CTX_set_keylog_callback(ctx, keylog_cb);
    return (jlong)(intptr_t)ctx;
}

// A server: its certificate chain and key, PEM. No tickets, no resumption. 0 - they are not good.
static SSL_CTX *server_context(const void *c_pem, int c_len, const void *k_pem, int k_len)
{
    if (ex_index < 0)
        ex_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    if (!ctx || !SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) || !SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION))
        return 0;
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_num_tickets(ctx, 0);
    SSL_CTX_set_keylog_callback(ctx, keylog_cb);
    int ok = 0;
    BIO *c_bio = c_pem ? BIO_new_mem_buf(c_pem, c_len) : NULL, *k_bio = k_pem ? BIO_new_mem_buf(k_pem, k_len) : NULL;
    if (c_bio && k_bio)
    {
        X509 *leaf = PEM_read_bio_X509(c_bio, NULL, NULL, NULL);
        EVP_PKEY *pkey = PEM_read_bio_PrivateKey(k_bio, NULL, NULL, NULL);
        ok = leaf && pkey && SSL_CTX_use_certificate(ctx, leaf) && SSL_CTX_use_PrivateKey(ctx, pkey) && SSL_CTX_check_private_key(ctx);
        for (X509 *more; ok && (more = PEM_read_bio_X509(c_bio, NULL, NULL, NULL)) != NULL;)
            if (!SSL_CTX_add0_chain_cert(ctx, more))
            {
                X509_free(more);
                ok = 0;
            }
        ERR_clear_error(); // the end of the chain is reported as an error
        X509_free(leaf);
        EVP_PKEY_free(pkey);
    }
    BIO_free(c_bio);
    BIO_free(k_bio);
    if (!ok)
    {
        SSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

FN(jlong, newServerContext)(JNIEnv *env, jclass cls, jbyteArray chain, jbyteArray key)
{
    jbyte *c_pem = (*env)->GetByteArrayElements(env, chain, NULL), *k_pem = (*env)->GetByteArrayElements(env, key, NULL);
    SSL_CTX *ctx = server_context(c_pem, (*env)->GetArrayLength(env, chain), k_pem, (*env)->GetArrayLength(env, key));
    if (c_pem)
        (*env)->ReleaseByteArrayElements(env, chain, c_pem, JNI_ABORT);
    if (k_pem)
        (*env)->ReleaseByteArrayElements(env, key, k_pem, JNI_ABORT);
    return (jlong)(intptr_t)ctx;
}

FN(jlong, newServerConnection)(JNIEnv *env, jclass cls, jlong ctx)
{
    Conn *c = (Conn *)calloc(1, sizeof(Conn));
    if (!c)
        return 0;
    c->pending_alert = -1;
    c->tx_limit = 1ull << 24;
    c->server = 1;
    c->verified = 1; // nothing to verify: clients bring no certificates
    c->ssl = SSL_new((SSL_CTX *)(intptr_t)ctx);
    c->rbio = BIO_new(BIO_s_mem());
    c->wbio = BIO_new(BIO_s_mem());
    if (!c->ssl || !c->rbio || !c->wbio)
        return (jlong)(intptr_t)c; // the first handshake call reports it
    BIO_set_mem_eof_return(c->rbio, -1);
    SSL_set_bio(c->ssl, c->rbio, c->wbio);
    SSL_set_ex_data(c->ssl, ex_index, c);
    SSL_set_accept_state(c->ssl);
    return (jlong)(intptr_t)c;
}

static jlong client_connection(jlong ctx, const char *host, const uint8_t *alpn, size_t alpn_len)
{
    Conn *c = (Conn *)calloc(1, sizeof(Conn));
    if (!c)
        return 0;
    c->pending_alert = -1;
    c->tx_limit = 1ull << 24; // RFC 8446 5.5: AES-GCM stands 2^24.5 full records under one key
    if (host)
    {
        const size_t n = strlen(host) + 1;
        if ((c->host = (char *)malloc(n)) != NULL)
            memcpy(c->host, host, n);
    }
    c->ssl = SSL_new((SSL_CTX *)(intptr_t)ctx);
    c->rbio = BIO_new(BIO_s_mem());
    c->wbio = BIO_new(BIO_s_mem());
    if (!c->host || !c->ssl || !c->rbio || !c->wbio)
        return (jlong)(intptr_t)c; // the first handshake call reports it
    BIO_set_mem_eof_return(c->rbio, -1);
    SSL_set_bio(c->ssl, c->rbio, c->wbio);
    SSL_set_ex_data(c->ssl, ex_index, c);
    SSL_set_connect_state(c->ssl);
    if (!is_ip(c->host))
        SSL_set_tlsext_host_name(c->ssl, c->host);
    if (alpn && alpn_len < 255)
    {
        uint8_t protos[256];
        protos[0] = (uint8_t)alpn_len;
        memcpy(protos + 1, alpn, alpn_len);
        SSL_set_alpn_protos(c->ssl, protos, alpn_len + 1);
    }
    return (jlong)(intptr_t)c;
}

FN(jlong, newConnection)(JNIEnv *env, jclass cls, jlong ctx, jstring jhost, jbyteArray jalpn)
{
    const char *host = (*env)->GetStringUTFChars(env, jhost, NULL);
    uint8_t alpn[256];
    jsize n = 0;
    if (jalpn && (n = (*env)->GetArrayLength(env, jalpn)) < (jsize)sizeof alpn)
        (*env)->GetByteArrayRegion(env, jalpn, 0, n, (jbyte *)alpn);
    const jlong c = client_connection(ctx, host, jalpn && n < (jsize)sizeof alpn ? alpn : NULL, (size_t)n);
    if (host)
        (*env)->ReleaseStringUTFChars(env, jhost, host);
    return c;
}

// status << 48 | consumed << 24 | produced
FN(jlong, handshake)(JNIEnv *env, jobject self, jlong conn, jlong in, jint in_len, jlong out, jint out_cap)
{
    Conn *c = (Conn *)(intptr_t)conn;
    if (!c->ssl)
        return c->error = c->error ? c->error : "no handshake", (jlong)FAILED << 48;
    c->env = env;
    c->owner = self;
    const uint8_t *from = (const uint8_t *)(intptr_t)in;
    uint8_t *to = (uint8_t *)(intptr_t)out;
    jlong consumed = 0, produced = 0;
    int status;
    for (;;)
    {
        const int ret = SSL_do_handshake(c->ssl);
        int n;
        while (produced < out_cap && (n = BIO_read(c->wbio, to + produced, (int)(out_cap - produced))) > 0)
            produced += n;
        if (ret == 1)
        {
            if (BIO_pending(c->wbio) != 0)
            {
                c->error = "the output buffer is too small";
                status = FAILED;
            }
            else
                status = finish_handshake(c) ? DONE : FAILED;
            break;
        }
        if (SSL_get_error(c->ssl, ret) != SSL_ERROR_WANT_READ)
        {
            if (!c->error)
                note(c, "handshake");
            status = FAILED;
            break;
        }
        const jlong left = in_len - consumed;
        // Not a record at all, a plain HTTP request on a TLS port say: its header would read as a length to wait for.
        if (0 < left && (from[consumed] < 20 || 23 < from[consumed] || 1 < left && from[consumed + 1] != 3))
        {
            c->error = "not TLS";
            status = FAILED;
            break;
        }
        if (left < HEADER)
        {
            status = NEED_READ;
            break;
        }
        const jlong len = HEADER + ((jlong)from[consumed + 3] << 8 | from[consumed + 4]);
        if (len > HEADER + MAX_CIPHERTEXT)
        {
            c->error = "too long a record";
            status = FAILED;
            break;
        }
        if (left < len)
        {
            status = NEED_READ;
            break;
        }
        // One record at a time: BoringSSL never holds a byte past its last message, what follows stays for open().
        if (BIO_write(c->rbio, from + consumed, (int)len) != (int)len)
        {
            note(c, "BIO_write");
            status = FAILED;
            break;
        }
        consumed += len;
    }
    if (status == FAILED)
        release_handshake(c);
    c->env = NULL;
    c->owner = NULL;
    return (jlong)status << 48 | consumed << 24 | produced;
}

FN(jint, seal)(JNIEnv *env, jclass cls, jlong conn, jlong rec, jint len)
{
    Conn *c = (Conn *)(intptr_t)conn;
    const int n = seal(c, (uint8_t *)(intptr_t)rec, (size_t)len, APPLICATION_DATA, 0);
    return c->pending_key_update ? n | NEEDS_CONTROL : n;
}

FN(jint, sealRaw)(JNIEnv *env, jclass cls, jlong conn, jlong rec, jint len, jint type, jint padding) { return seal((Conn *)(intptr_t)conn, (uint8_t *)(intptr_t)rec, (size_t)len, type, (size_t)padding); }

FN(jlong, open)(JNIEnv *env, jclass cls, jlong conn, jlong rec, jint have) { return open_record((Conn *)(intptr_t)conn, (uint8_t *)(intptr_t)rec, (size_t)have); }

// All the whole records from `at` below `limit`, in one call: their data drawn together behind `at`, with no copy for the first.
// Bits 40.. the end of what is consumed, bits 2..39 the end of the data, bit 1 a control record waits, bit 0 closed. -1 - over.
FN(jlong, openAll)(JNIEnv *env, jclass cls, jlong conn, jlong address, jint at, jint limit)
{
    Conn *c = (Conn *)(intptr_t)conn;
    uint8_t *base = (uint8_t *)(intptr_t)address;
    size_t from = (size_t)at, to = (size_t)at;
    for (;;)
    {
        const jlong r = open_record(c, base + from, (size_t)limit - from);
        if (r < 0)
            return -1;
        if (r == 0)
            break;
        const size_t total = (size_t)(r >> 32), data = (size_t)(r & 0xFFFF);
        if (data != 0)
        {
            if (to != from + HEADER)
                memmove(base + to, base + from + HEADER, data);
            to += data;
        }
        from += total;
        if (c->closed)
        {
            from = (size_t)limit;
            break;
        }
    }
    const int control = c->pending_key_update || c->pending_alert >= 0;
    return (jlong)from << 40 | (jlong)to << 2 | (control ? 2 : 0) | (c->closed ? 1 : 0);
}

FN(jint, control)(JNIEnv *env, jclass cls, jlong conn, jlong rec)
{
    Conn *c = (Conn *)(intptr_t)conn;
    uint8_t *body = (uint8_t *)(intptr_t)rec + HEADER;
    if (c->pending_alert >= 0)
    {
        const int code = c->pending_alert;
        c->pending_alert = -1;
        c->pending_key_update = 0;
        body[0] = code == CLOSE_NOTIFY || code == USER_CANCELED ? 1 : 2;
        body[1] = (uint8_t)code;
        return seal(c, (uint8_t *)(intptr_t)rec, 2, ALERT, 0);
    }
    if (!c->pending_key_update)
        return 0;
    body[0] = KEY_UPDATE, body[1] = 0, body[2] = 0, body[3] = 1, body[4] = 0;
    const int n = seal(c, (uint8_t *)(intptr_t)rec, 5, HANDSHAKE, 0);
    c->pending_key_update = 0;
    if (n < 0 || !next_secret(c, c->tx_secret) || !install(c, c->tx_secret, &c->tx, c->tx_iv, &c->tx_seq))
        return -1;
    c->tx_updates++;
    return n;
}

FN(void, closeNotify)(JNIEnv *env, jclass cls, jlong conn) { ((Conn *)(intptr_t)conn)->pending_alert = CLOSE_NOTIFY; }

FN(void, txLimit)(JNIEnv *env, jclass cls, jlong conn, jlong limit) { ((Conn *)(intptr_t)conn)->tx_limit = (uint64_t)limit; }

FN(jint, info)(JNIEnv *env, jclass cls, jlong conn, jint what)
{
    const Conn *c = (const Conn *)(intptr_t)conn;
    return what == 0 ? c->cipher : what == 1 ? c->tx_updates : what == 2 ? c->rx_updates : what == 3 ? c->group : (int)sizeof(Conn);
}

FN(jstring, groupName)(JNIEnv *env, jclass cls, jint id)
{
    const char *name = SSL_get_group_name((uint16_t)id);
    return (*env)->NewStringUTF(env, name ? name : "?");
}

FN(jstring, error)(JNIEnv *env, jclass cls, jlong conn)
{
    const Conn *c = (const Conn *)(intptr_t)conn;
    return (*env)->NewStringUTF(env, c->error ? c->error : "unknown");
}

// The record layer alone, both directions under one secret: for tests and measurements.
FN(jlong, recordsOnly0)(JNIEnv *env, jclass cls, jint cipher, jbyteArray secret)
{
    Conn *c = (Conn *)calloc(1, sizeof(Conn));
    if (!c)
        return 0;
    c->pending_alert = -1;
    c->tx_limit = 1ull << 24;
    (*env)->GetByteArrayRegion(env, secret, 0, (*env)->GetArrayLength(env, secret), (jbyte *)c->tx_secret);
    memcpy(c->rx_secret, c->tx_secret, sizeof c->rx_secret);
    if (!schedule(c, cipher))
    {
        free(c);
        return 0;
    }
    return (jlong)(intptr_t)c;
}

FN(void, free)(JNIEnv *env, jclass cls, jlong conn)
{
    Conn *c = (Conn *)(intptr_t)conn;
    if (!c)
        return;
    release_handshake(c);
    if (c->tx)
        EVP_AEAD_CTX_free(c->tx);
    if (c->rx)
        EVP_AEAD_CTX_free(c->rx);
    free(c->partial);
    OPENSSL_cleanse(c, sizeof(Conn));
    free(c);
}

//#endregion

//#region the primitives
#define CRYPTO(ret, name) JNIEXPORT ret JNICALL Java_org_unirail_crypto_Crypto_##name
#define ADDR(type, x) ((type *)(intptr_t)(x))

JNIEXPORT jint JNICALL Java_org_unirail_crypto_Native_abi(JNIEnv *env, jclass cls) { return 9; }

CRYPTO(jlong, address0)(JNIEnv *env, jclass cls, jobject direct) { return (jlong)(intptr_t)(*env)->GetDirectBufferAddress(env, direct); }

CRYPTO(jint, aeadSize)(JNIEnv *env, jclass cls) { return (jint)sizeof(EVP_AEAD_CTX); }

// The context lies in the memory the caller gives: a direct buffer, freed with it. Expanded once.
CRYPTO(jboolean, aeadInit)(JNIEnv *env, jclass cls, jint kind, jlong ctx, jbyteArray key)
{
    const EVP_AEAD *aead = kind == 0 ? EVP_aead_chacha20_poly1305() : kind == 1 ? EVP_aead_aes_128_gcm() : kind == 2 ? EVP_aead_aes_256_gcm() : NULL;
    if (!aead || (size_t)(*env)->GetArrayLength(env, key) != EVP_AEAD_key_length(aead))
        return JNI_FALSE;
    uint8_t k[32];
    (*env)->GetByteArrayRegion(env, key, 0, (jsize)EVP_AEAD_key_length(aead), (jbyte *)k);
    const int ok = EVP_AEAD_CTX_init(ADDR(EVP_AEAD_CTX, ctx), aead, k, EVP_AEAD_key_length(aead), TAG, NULL);
    OPENSSL_cleanse(k, sizeof k);
    ERR_clear_error();
    return ok ? JNI_TRUE : JNI_FALSE;
}

// The nonce of Noise: 0^4 || n, little-endian.
static inline void noise_nonce(uint8_t nonce[12], uint64_t n)
{
    memset(nonce, 0, 4);
    for (int i = 0; i < 8; i++)
        nonce[4 + i] = (uint8_t)(n >> (8 * i));
}

static inline int aead_seal(const EVP_AEAD_CTX *ctx, const uint8_t *nonce, const uint8_t *ad, size_t ad_len, uint8_t *p, size_t len)
{
    size_t tag_len;
    if (EVP_AEAD_CTX_seal_scatter(ctx, p, p + len, &tag_len, TAG, nonce, 12, p, len, NULL, 0, ad, ad_len))
        return 1;
    ERR_clear_error();
    return 0;
}

// False: forged, and BoringSSL has cleared the text: nothing of it can be taken for data.
static inline int aead_open(const EVP_AEAD_CTX *ctx, const uint8_t *nonce, const uint8_t *ad, size_t ad_len, uint8_t *p, size_t len)
{
    if (EVP_AEAD_CTX_open_gather(ctx, p, nonce, 12, p, len, p + len, TAG, ad, ad_len))
        return 1;
    ERR_clear_error();
    return 0;
}

CRYPTO(jboolean, seal)(JNIEnv *env, jclass cls, jlong ctx, jlong n, jlong ad, jint ad_len, jlong text, jint len)
{
    uint8_t nonce[12];
    noise_nonce(nonce, (uint64_t)n);
    return (jboolean)aead_seal(ADDR(EVP_AEAD_CTX, ctx), nonce, ADDR(uint8_t, ad), (size_t)ad_len, ADDR(uint8_t, text), (size_t)len);
}

CRYPTO(jboolean, open)(JNIEnv *env, jclass cls, jlong ctx, jlong n, jlong ad, jint ad_len, jlong text, jint len)
{
    uint8_t nonce[12];
    noise_nonce(nonce, (uint64_t)n);
    return (jboolean)aead_open(ADDR(EVP_AEAD_CTX, ctx), nonce, ADDR(uint8_t, ad), (size_t)ad_len, ADDR(uint8_t, text), (size_t)len);
}

// The same over arrays, for what does not lie in a direct buffer. nonce null - that of Noise, from n.
static jboolean aead_arrays(JNIEnv *env, int sealing, jlong ctx, jbyteArray jnonce, jlong n, jbyteArray jad, jint ad_at, jint ad_len, jbyteArray jdata, jint at, jint len)
{
    uint8_t nonce[12];
    if (jnonce)
        (*env)->GetByteArrayRegion(env, jnonce, 0, 12, (jbyte *)nonce);
    else
        noise_nonce(nonce, (uint64_t)n);
    uint8_t *data = (uint8_t *)(*env)->GetPrimitiveArrayCritical(env, jdata, NULL);
    if (!data)
        return JNI_FALSE;
    uint8_t *ad = jad == NULL ? NULL : jad == jdata ? data : (uint8_t *)(*env)->GetPrimitiveArrayCritical(env, jad, NULL);
    const uint8_t *adp = ad ? ad + ad_at : NULL;
    const int ok = sealing ? aead_seal(ADDR(EVP_AEAD_CTX, ctx), nonce, adp, (size_t)ad_len, data + at, (size_t)len) : aead_open(ADDR(EVP_AEAD_CTX, ctx), nonce, adp, (size_t)ad_len, data + at, (size_t)len);
    if (ad && jad != jdata)
        (*env)->ReleasePrimitiveArrayCritical(env, jad, ad, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, jdata, data, 0);
    return ok ? JNI_TRUE : JNI_FALSE;
}

CRYPTO(jboolean, sealArrays)(JNIEnv *env, jclass cls, jlong ctx, jbyteArray nonce, jlong n, jbyteArray ad, jint ad_at, jint ad_len, jbyteArray data, jint at, jint len) { return aead_arrays(env, 1, ctx, nonce, n, ad, ad_at, ad_len, data, at, len); }

CRYPTO(jboolean, openArrays)(JNIEnv *env, jclass cls, jlong ctx, jbyteArray nonce, jlong n, jbyteArray ad, jint ad_at, jint ad_len, jbyteArray data, jint at, jint len) { return aead_arrays(env, 0, ctx, nonce, n, ad, ad_at, ad_len, data, at, len); }

// The records of Noise.Stream, [length 2, little-endian][text][tag 16], the length the associated data, the count the nonce.
// All those a buffer holds, in one call. The texts are there, the lengths written: sealed in place.
CRYPTO(jlong, sealRecords)(JNIEnv *env, jclass cls, jlong ctx, jlong n, jlong address, jint bytes)
{
    uint8_t *p = ADDR(uint8_t, address), nonce[12];
    for (size_t at = 0; at < (size_t)bytes;)
    {
        const size_t len = (size_t)p[at] | (size_t)p[at + 1] << 8;
        noise_nonce(nonce, (uint64_t)n);
        if (!aead_seal(ADDR(EVP_AEAD_CTX, ctx), nonce, p + at, 2, p + at + 2, len))
            return -1;
        n++;
        at += 2 + len + TAG;
    }
    return n;
}

// All the whole records at the address, opened in place; the lengths stay, so the caller walks them with no more calls.
// opened bytes << 32 | records; -1 - forged, or a length no record can have.
CRYPTO(jlong, openRecords)(JNIEnv *env, jclass cls, jlong ctx, jlong n, jlong address, jint have, jint max)
{
    uint8_t *p = ADDR(uint8_t, address), nonce[12];
    size_t at = 0;
    jlong count = 0;
    while ((size_t)have - at >= 2)
    {
        const size_t len = (size_t)p[at] | (size_t)p[at + 1] << 8;
        if (len == 0 || (size_t)max < len)
            return -1;
        if ((size_t)have - at < 2 + len + TAG)
            break;
        noise_nonce(nonce, (uint64_t)n);
        if (!aead_open(ADDR(EVP_AEAD_CTX, ctx), nonce, p + at, 2, p + at + 2, len))
            return -1;
        n++;
        count++;
        at += 2 + len + TAG;
    }
    return (jlong)at << 32 | count;
}

// The keystream of a stage. Java writes the key, the nonce and the counter into this memory itself: no call for a new pack.
typedef struct
{
    uint8_t key[32], nonce[12];
    uint32_t counter;
    uint32_t pos; // into ks; 64 - used up
    uint8_t ks[64];
} Stream;

CRYPTO(jint, streamSize)(JNIEnv *env, jclass cls) { return (jint)sizeof(Stream); }

static void stream_xor(Stream *s, uint8_t *p, size_t len)
{
    while (s->pos < 64 && len != 0)
    {
        *p++ ^= s->ks[s->pos++];
        len--;
    }
    const size_t blocks = len / 64;
    if (blocks != 0)
    {
        CRYPTO_chacha_20(p, p, blocks * 64, s->key, s->nonce, s->counter);
        s->counter += (uint32_t)blocks;
        p += blocks * 64;
        len -= blocks * 64;
    }
    if (len != 0)
    {
        memset(s->ks, 0, 64);
        CRYPTO_chacha_20(s->ks, s->ks, 64, s->key, s->nonce, s->counter++);
        for (s->pos = 0; s->pos < len; s->pos++)
            p[s->pos] ^= s->ks[s->pos];
    }
}

CRYPTO(void, streamXor)(JNIEnv *env, jclass cls, jlong state, jlong address, jint len) { stream_xor(ADDR(Stream, state), ADDR(uint8_t, address), (size_t)len); }

CRYPTO(void, streamXorArray)(JNIEnv *env, jclass cls, jlong state, jbyteArray data, jint at, jint len)
{
    uint8_t *a = (uint8_t *)(*env)->GetPrimitiveArrayCritical(env, data, NULL);
    if (!a)
        return;
    stream_xor(ADDR(Stream, state), a + at, (size_t)len);
    (*env)->ReleasePrimitiveArrayCritical(env, data, a, 0);
}

CRYPTO(void, chacha20)(JNIEnv *env, jclass cls, jlong out, jlong in, jlong len, jlong key, jlong nonce, jint counter) { CRYPTO_chacha_20(ADDR(uint8_t, out), ADDR(const uint8_t, in), (size_t)len, ADDR(const uint8_t, key), ADDR(const uint8_t, nonce), (uint32_t)counter); }

CRYPTO(void, poly1305)(JNIEnv *env, jclass cls, jlong out, jlong key, jlong in, jlong len)
{
    poly1305_state state;
    CRYPTO_poly1305_init(&state, ADDR(const uint8_t, key));
    CRYPTO_poly1305_update(&state, ADDR(const uint8_t, in), (size_t)len);
    CRYPTO_poly1305_finish(&state, ADDR(uint8_t, out));
}

CRYPTO(void, sha256)(JNIEnv *env, jclass cls, jlong out, jlong in, jlong len) { SHA256(ADDR(const uint8_t, in), (size_t)len, ADDR(uint8_t, out)); }

CRYPTO(void, hmacSha256)(JNIEnv *env, jclass cls, jlong out, jlong key, jint key_len, jlong in, jlong len)
{
    unsigned n = 32;
    HMAC(EVP_sha256(), ADDR(const void, key), (size_t)key_len, ADDR(const uint8_t, in), (size_t)len, ADDR(uint8_t, out), &n);
}

CRYPTO(void, random)(JNIEnv *env, jclass cls, jbyteArray out)
{
    const jsize n = (*env)->GetArrayLength(env, out);
    uint8_t *a = (uint8_t *)(*env)->GetPrimitiveArrayCritical(env, out, NULL);
    if (!a)
        return;
    RAND_bytes(a, (size_t)n);
    (*env)->ReleasePrimitiveArrayCritical(env, out, a, 0);
}

// False: a low-order peer key, the shared secret would be zeros.
CRYPTO(jboolean, x25519)(JNIEnv *env, jclass cls, jbyteArray shared, jbyteArray secret, jbyteArray peer)
{
    uint8_t out[32], s[32], p[32];
    (*env)->GetByteArrayRegion(env, secret, 0, 32, (jbyte *)s);
    (*env)->GetByteArrayRegion(env, peer, 0, 32, (jbyte *)p);
    const int ok = X25519(out, s, p);
    OPENSSL_cleanse(s, sizeof s);
    (*env)->SetByteArrayRegion(env, shared, 0, 32, (const jbyte *)out);
    OPENSSL_cleanse(out, sizeof out);
    return ok ? JNI_TRUE : JNI_FALSE;
}

CRYPTO(void, x25519Public)(JNIEnv *env, jclass cls, jbyteArray pub, jbyteArray secret)
{
    uint8_t out[32], s[32];
    (*env)->GetByteArrayRegion(env, secret, 0, 32, (jbyte *)s);
    X25519_public_from_private(out, s);
    OPENSSL_cleanse(s, sizeof s);
    (*env)->SetByteArrayRegion(env, pub, 0, 32, (const jbyte *)out);
}

CRYPTO(void, x25519KeyPair)(JNIEnv *env, jclass cls, jbyteArray secret, jbyteArray pub)
{
    uint8_t p[32], s[32];
    X25519_keypair(p, s);
    (*env)->SetByteArrayRegion(env, secret, 0, 32, (const jbyte *)s);
    (*env)->SetByteArrayRegion(env, pub, 0, 32, (const jbyte *)p);
    OPENSSL_cleanse(s, sizeof s);
}

// E7: Ed25519. `secret` is the 64 bytes of BoringSSL: the seed and the public key.
CRYPTO(void, ed25519KeyPair)(JNIEnv *env, jclass cls, jbyteArray secret, jbyteArray pub, jbyteArray seed)
{
    uint8_t p[32], s[64], given[32];
    if (seed)
    {
        (*env)->GetByteArrayRegion(env, seed, 0, 32, (jbyte *)given);
        ED25519_keypair_from_seed(p, s, given);
        OPENSSL_cleanse(given, sizeof given);
    }
    else
        ED25519_keypair(p, s);
    (*env)->SetByteArrayRegion(env, secret, 0, 64, (const jbyte *)s);
    (*env)->SetByteArrayRegion(env, pub, 0, 32, (const jbyte *)p);
    OPENSSL_cleanse(s, sizeof s);
}

CRYPTO(jboolean, ed25519Sign)(JNIEnv *env, jclass cls, jbyteArray signature, jbyteArray secret, jlong message, jlong len)
{
    uint8_t out[64], s[64];
    (*env)->GetByteArrayRegion(env, secret, 0, 64, (jbyte *)s);
    const int ok = ED25519_sign(out, ADDR(const uint8_t, message), (size_t)len, s);
    OPENSSL_cleanse(s, sizeof s);
    (*env)->SetByteArrayRegion(env, signature, 0, 64, (const jbyte *)out);
    return ok ? JNI_TRUE : JNI_FALSE;
}

CRYPTO(jboolean, ed25519Verify)(JNIEnv *env, jclass cls, jbyteArray signature, jbyteArray pub, jlong message, jlong len)
{
    uint8_t sig[64], p[32];
    (*env)->GetByteArrayRegion(env, signature, 0, 64, (jbyte *)sig);
    (*env)->GetByteArrayRegion(env, pub, 0, 32, (jbyte *)p);
    return ED25519_verify(ADDR(const uint8_t, message), (size_t)len, sig, p) ? JNI_TRUE : JNI_FALSE;
}

// E6: the key of a pair. Both sides get the same from their own secret and the other's public key: the DH through HKDF, the
// two public keys in order and the label as what it is for. 32 of key, 12 of base nonce, 4 of id (never 0). False: a low-order key.
static int pair_key(uint8_t *key, uint8_t *iv, int32_t *id, const uint8_t *secret, const uint8_t *their, const uint8_t *label, size_t n)
{
    uint8_t mine[32], dh[32], out[48], info[64 + 255];
    if (n > 255)
        return 0;
    X25519_public_from_private(mine, secret);
    if (!X25519(dh, secret, their))
    {
        OPENSSL_cleanse(dh, sizeof dh);
        return 0;
    }
    const int order = memcmp(mine, their, 32) < 0;
    memcpy(info, order ? mine : their, 32);
    memcpy(info + 32, order ? their : mine, 32);
    memcpy(info + 64, label, n);
    const int done = HKDF(out, sizeof out, EVP_sha256(), dh, sizeof dh, NULL, 0, info, 64 + n);
    OPENSSL_cleanse(dh, sizeof dh);
    if (!done)
        return 0;
    memcpy(key, out, 32);
    memcpy(iv, out + 32, 12);
    const int32_t i = (int32_t)((uint32_t)out[44] | (uint32_t)out[45] << 8 | (uint32_t)out[46] << 16 | (uint32_t)out[47] << 24);
    *id = i == 0 ? 1 : i;
    OPENSSL_cleanse(out, sizeof out);
    return 1;
}

CRYPTO(jboolean, pairKey)(JNIEnv *env, jclass cls, jbyteArray key, jbyteArray iv, jintArray id, jbyteArray secret, jbyteArray their, jbyteArray label)
{
    uint8_t s[32], other[32], k[32], v[12], text[255];
    const jsize n = (*env)->GetArrayLength(env, label);
    if (n > 255)
        return JNI_FALSE;
    (*env)->GetByteArrayRegion(env, secret, 0, 32, (jbyte *)s);
    (*env)->GetByteArrayRegion(env, their, 0, 32, (jbyte *)other);
    (*env)->GetByteArrayRegion(env, label, 0, n, (jbyte *)text);
    jint i = 0;
    const int ok = pair_key(k, v, &i, s, other, text, (size_t)n);
    OPENSSL_cleanse(s, sizeof s);
    if (!ok)
        return JNI_FALSE;
    (*env)->SetByteArrayRegion(env, key, 0, 32, (const jbyte *)k);
    (*env)->SetByteArrayRegion(env, iv, 0, 12, (const jbyte *)v);
    (*env)->SetIntArrayRegion(env, id, 0, 1, &i);
    OPENSSL_cleanse(k, sizeof k);
    return JNI_TRUE;
}
//#endregion

//#region Noise: the whole handshake of a message in one call; when it ends the keys are there, and nothing of them passed through Java
enum { T_E, T_S, T_EE, T_ES, T_SE, T_SS, T_END };
enum { NK = 0, IK = 1, XX = 2, KK = 3 };

static const uint8_t PATTERNS[4][3][6] = {
    {{T_E, T_ES, T_END}, {T_E, T_EE, T_END}, {T_END}},
    {{T_E, T_ES, T_S, T_SS, T_END}, {T_E, T_EE, T_SE, T_END}, {T_END}},
    {{T_E, T_END}, {T_E, T_EE, T_S, T_ES, T_END}, {T_S, T_SE, T_END}},
    {{T_E, T_ES, T_SS, T_END}, {T_E, T_EE, T_SE, T_END}, {T_END}},
};
static const uint8_t PATTERN_MESSAGES[4] = {2, 2, 3, 2};
static const char *const PATTERN_NAMES[4] = {"Noise_NK_25519_ChaChaPoly_SHA256", "Noise_IK_25519_ChaChaPoly_SHA256", "Noise_XX_25519_ChaChaPoly_SHA256", "Noise_KK_25519_ChaChaPoly_SHA256"};

// Java reads the first fields where they lie: 0, 32, 64, 76, 80.
typedef struct
{
    uint8_t h[32], pack_key[32], pack_iv[12];
    int32_t done;
    uint8_t peer[32];
    uint8_t ck[32], k[32];
    uint64_t n;
    int32_t has_key, initiator, pattern, message, has_s, has_rs;
    uint8_t e_secret[32], e_public[32], s_secret[32], s_public[32], re[32];
    EVP_AEAD_CTX tx, rx;
} Hs;

CRYPTO(jint, noiseSize)(JNIEnv *env, jclass cls) { return (jint)sizeof(Hs); }
CRYPTO(jint, noiseTx)(JNIEnv *env, jclass cls) { return (jint)offsetof(Hs, tx); }
CRYPTO(jint, noiseRx)(JNIEnv *env, jclass cls) { return (jint)offsetof(Hs, rx); }

static void mix_hash(Hs *s, const uint8_t *data, size_t len)
{
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, s->h, 32);
    SHA256_Update(&c, data, len);
    SHA256_Final(s->h, &c);
}

// Noise's HKDF: two outputs of 32 bytes. out1 may be the chaining key itself.
static void hkdf2(const uint8_t *chaining, const uint8_t *ikm, size_t ikm_len, uint8_t *out1, uint8_t *out2)
{
    uint8_t temp[32], o1[32], block[33];
    unsigned n = 32;
    HMAC(EVP_sha256(), chaining, 32, ikm, ikm_len, temp, &n);
    block[0] = 1;
    HMAC(EVP_sha256(), temp, 32, block, 1, o1, &n);
    memcpy(block, o1, 32);
    block[32] = 2;
    HMAC(EVP_sha256(), temp, 32, block, 33, out2, &n);
    memcpy(out1, o1, 32);
    OPENSSL_cleanse(temp, sizeof temp);
    OPENSSL_cleanse(o1, sizeof o1);
    OPENSSL_cleanse(block, sizeof block);
}

static int mix_dh(Hs *s, const uint8_t *secret, const uint8_t *pub)
{
    uint8_t dh[32];
    const int ok = X25519(dh, secret, pub);
    hkdf2(s->ck, dh, 32, s->ck, s->k);
    OPENSSL_cleanse(dh, sizeof dh);
    s->has_key = 1;
    s->n = 0;
    return ok;
}

static int token_dh(Hs *s, int token)
{
    const int i = s->initiator;
    switch (token)
    {
        case T_EE: return mix_dh(s, s->e_secret, s->re);
        case T_ES: return i ? mix_dh(s, s->e_secret, s->peer) : mix_dh(s, s->s_secret, s->re);
        case T_SE: return i ? mix_dh(s, s->s_secret, s->re) : mix_dh(s, s->e_secret, s->peer);
        default: return mix_dh(s, s->s_secret, s->peer);
    }
}

// In place: the text at c, then room for the tag. The length of what goes on the wire.
static size_t encrypt_and_hash(Hs *s, uint8_t *c, size_t len)
{
    size_t total = len;
    if (s->has_key)
    {
        EVP_AEAD_CTX ctx;
        uint8_t nonce[12];
        size_t tag_len;
        noise_nonce(nonce, s->n++);
        EVP_AEAD_CTX_init(&ctx, EVP_aead_chacha20_poly1305(), s->k, 32, TAG, NULL);
        EVP_AEAD_CTX_seal_scatter(&ctx, c, c + len, &tag_len, TAG, nonce, 12, c, len, NULL, 0, s->h, 32);
        EVP_AEAD_CTX_cleanup(&ctx);
        total += TAG;
    }
    mix_hash(s, c, total);
    return total;
}

// `total` bytes at c; the text goes to out. 0 - forged.
static int decrypt_and_hash(Hs *s, const uint8_t *c, size_t total, uint8_t *out)
{
    if (!s->has_key)
        memcpy(out, c, total);
    else
    {
        EVP_AEAD_CTX ctx;
        uint8_t nonce[12];
        size_t got;
        noise_nonce(nonce, s->n++);
        EVP_AEAD_CTX_init(&ctx, EVP_aead_chacha20_poly1305(), s->k, 32, TAG, NULL);
        const int ok = EVP_AEAD_CTX_open(&ctx, out, &got, total, nonce, 12, c, total, s->h, 32);
        EVP_AEAD_CTX_cleanup(&ctx);
        if (!ok)
        {
            ERR_clear_error();
            return 0;
        }
    }
    mix_hash(s, c, total);
    return 1;
}

static const uint8_t PACKS[] = "AdHoc packs";

// The last message is done: the transport keys and the key of the packs, and nothing else of the handshake stays.
static void hs_finish(Hs *s)
{
    uint8_t k1[32], k2[32], more[32];
    hkdf2(s->ck, NULL, 0, k1, k2);
    EVP_AEAD_CTX_init(&s->tx, EVP_aead_chacha20_poly1305(), s->initiator ? k1 : k2, 32, TAG, NULL);
    EVP_AEAD_CTX_init(&s->rx, EVP_aead_chacha20_poly1305(), s->initiator ? k2 : k1, 32, TAG, NULL);
    hkdf2(s->ck, PACKS, sizeof PACKS - 1, s->pack_key, more);
    memcpy(s->pack_iv, more, 12);
    OPENSSL_cleanse(k1, sizeof k1);
    OPENSSL_cleanse(k2, sizeof k2);
    OPENSSL_cleanse(more, sizeof more);
    OPENSSL_cleanse(s->ck, sizeof s->ck);
    OPENSSL_cleanse(s->k, sizeof s->k);
    OPENSSL_cleanse(s->e_secret, sizeof s->e_secret);
    OPENSSL_cleanse(s->s_secret, sizeof s->s_secret);
    s->done = 1;
}

// staticSecret: this side's, null when the pattern has none for it. peer: the other's static key known beforehand, null when not.
static void noise_init(jlong state, int pattern, int initiator, const uint8_t *pro, size_t pro_len, const uint8_t *static_secret, const uint8_t *static_public, const uint8_t *peer, const uint8_t *ephemeral)
{
    Hs *s = ADDR(Hs, state);
    memset(s, 0, sizeof(Hs));
    s->pattern = pattern;
    s->initiator = initiator;
    memcpy(s->h, PATTERN_NAMES[pattern], 32); // exactly HASHLEN: h is the name itself
    memcpy(s->ck, PATTERN_NAMES[pattern], 32);
    mix_hash(s, pro, pro_len);
    if (static_secret)
    {
        memcpy(s->s_secret, static_secret, 32);
        if (static_public)
            memcpy(s->s_public, static_public, 32);
        else
            X25519_public_from_private(s->s_public, s->s_secret);
        s->has_s = 1;
    }
    if (peer)
    {
        memcpy(s->peer, peer, 32);
        s->has_rs = 1;
    }
    // The pre-messages. NK, IK: <- s. KK: -> s, <- s. XX: none.
    if (pattern == KK)
        mix_hash(s, initiator ? s->s_public : s->peer, 32);
    if (pattern != XX)
        mix_hash(s, initiator ? s->peer : s->s_public, 32);
    if (ephemeral)
    {
        memcpy(s->e_secret, ephemeral, 32);
        X25519_public_from_private(s->e_public, s->e_secret);
    }
    else
        X25519_keypair(s->e_public, s->e_secret);
}

CRYPTO(void, noiseInit)(JNIEnv *env, jclass cls, jlong state, jint pattern, jboolean initiator, jbyteArray prologue, jbyteArray static_secret, jbyteArray static_public, jbyteArray peer, jbyteArray ephemeral)
{
    const jsize n = (*env)->GetArrayLength(env, prologue);
    uint8_t stack[256], *pro = n <= (jsize)sizeof stack ? stack : (uint8_t *)malloc((size_t)n), ss[32], sp[32], pe[32], ep[32];
    (*env)->GetByteArrayRegion(env, prologue, 0, n, (jbyte *)pro);
    if (static_secret)
        (*env)->GetByteArrayRegion(env, static_secret, 0, 32, (jbyte *)ss);
    if (static_public)
        (*env)->GetByteArrayRegion(env, static_public, 0, 32, (jbyte *)sp);
    if (peer)
        (*env)->GetByteArrayRegion(env, peer, 0, 32, (jbyte *)pe);
    if (ephemeral)
        (*env)->GetByteArrayRegion(env, ephemeral, 0, 32, (jbyte *)ep);
    noise_init(state, pattern, initiator, pro, (size_t)n, static_secret ? ss : NULL, static_public ? sp : NULL, peer ? pe : NULL, ephemeral ? ep : NULL);
    if (pro != stack)
        free(pro);
    OPENSSL_cleanse(ss, sizeof ss);
    OPENSSL_cleanse(ep, sizeof ep);
}

// This side's message at dst[at]. Its length; -1 - not this side's turn, a low-order key, or no room.
static jint noise_write(jlong state, uint8_t *dst, size_t cap, const uint8_t *payload, jint len)
{
    Hs *s = ADDR(Hs, state);
    if (s->done || (s->message & 1) != (s->initiator ? 0 : 1) || s->message >= PATTERN_MESSAGES[s->pattern])
        return -1;
    const size_t room = (size_t)len + 32 + 48 + TAG;
    uint8_t *m = (uint8_t *)malloc(room);
    if (!m)
        return -1;
    size_t w = 0;
    int ok = 1;
    for (const uint8_t *t = PATTERNS[s->pattern][s->message]; *t != T_END && ok; t++)
    {
        if (*t == T_E)
        {
            memcpy(m + w, s->e_public, 32);
            mix_hash(s, s->e_public, 32);
            w += 32;
        }
        else if (*t == T_S)
        {
            memcpy(m + w, s->s_public, 32);
            w += encrypt_and_hash(s, m + w, 32);
        }
        else
            ok = token_dh(s, *t);
    }
    if (ok)
    {
        if (len != 0)
            memcpy(m + w, payload, (size_t)len);
        w += encrypt_and_hash(s, m + w, (size_t)len);
        if (cap < w)
            ok = 0;
        else
            memcpy(dst, m, w);
    }
    OPENSSL_cleanse(m, room);
    free(m);
    if (!ok)
        return -1;
    if (++s->message == PATTERN_MESSAGES[s->pattern])
        hs_finish(s);
    return (jint)w;
}

CRYPTO(jint, noiseWrite)(JNIEnv *env, jclass cls, jlong state, jbyteArray dst, jint at, jbyteArray payload, jint off, jint len)
{
    const size_t cap = (size_t)(*env)->GetArrayLength(env, dst) - (size_t)at;
    uint8_t *p = len != 0 ? (uint8_t *)malloc((size_t)len) : NULL, *out = (uint8_t *)malloc(cap + 1);
    if (!out || (len != 0 && !p))
    {
        free(p);
        free(out);
        return -1;
    }
    if (len != 0)
        (*env)->GetByteArrayRegion(env, payload, off, len, (jbyte *)p);
    const jint w = noise_write(state, out, cap, p, len);
    if (0 < w)
        (*env)->SetByteArrayRegion(env, dst, at, w, (const jbyte *)out);
    if (p)
        OPENSSL_cleanse(p, (size_t)len);
    free(p);
    free(out);
    return w;
}

// The other side's message: its payload to payload[off]. The payload's length; -1 - out of turn, too short, a low-order key, or
// forged - and the state as it was: a forged message ahead of the real one spoils nothing.
static jint noise_read(jlong state, const uint8_t *msg, jint len, uint8_t *payload, size_t room)
{
    Hs *s = ADDR(Hs, state);
    if (s->done || (s->message & 1) != (s->initiator ? 1 : 0) || s->message >= PATTERN_MESSAGES[s->pattern] || len < 0)
        return -1;
    uint8_t *m = (uint8_t *)malloc((size_t)len + 64 + 48);
    if (!m)
        return -1;
    memcpy(m, msg, (size_t)len);
    uint8_t h[32], ck[32], k[32], re[32], peer[32];
    const uint64_t n = s->n;
    const int has_key = s->has_key, has_rs = s->has_rs;
    memcpy(h, s->h, 32), memcpy(ck, s->ck, 32), memcpy(k, s->k, 32), memcpy(re, s->re, 32), memcpy(peer, s->peer, 32);

    size_t r = 0, left = (size_t)len, text = 0;
    int ok = 1;
    uint8_t *body = NULL;
    for (const uint8_t *t = PATTERNS[s->pattern][s->message]; *t != T_END && ok; t++)
    {
        if (*t == T_E)
        {
            if (left < 32)
            {
                ok = 0;
                break;
            }
            memcpy(s->re, m + r, 32);
            mix_hash(s, s->re, 32);
            r += 32, left -= 32;
        }
        else if (*t == T_S)
        {
            const size_t size = s->has_key ? 32 + TAG : 32;
            uint8_t got[48];
            if (left < size || !decrypt_and_hash(s, m + r, size, got))
            {
                ok = 0;
                break;
            }
            memcpy(s->peer, got, 32);
            s->has_rs = 1;
            r += size, left -= size;
        }
        else
            ok = token_dh(s, *t);
    }
    if (ok)
    {
        const size_t overhead = s->has_key ? TAG : 0;
        if (left < overhead || room < left - overhead)
            ok = 0;
        else
        {
            text = left - overhead;
            body = (uint8_t *)malloc(left + 1);
            ok = body != NULL && decrypt_and_hash(s, m + r, left, body);
        }
    }
    if (ok && text != 0)
        memcpy(payload, body, text);
    if (body)
    {
        OPENSSL_cleanse(body, left + 1);
        free(body);
    }
    OPENSSL_cleanse(m, (size_t)len + 64 + 48);
    free(m);
    if (!ok)
    {
        memcpy(s->h, h, 32), memcpy(s->ck, ck, 32), memcpy(s->k, k, 32), memcpy(s->re, re, 32), memcpy(s->peer, peer, 32);
        s->n = n, s->has_key = has_key, s->has_rs = has_rs;
        OPENSSL_cleanse(k, sizeof k);
        OPENSSL_cleanse(ck, sizeof ck);
        return -1;
    }
    OPENSSL_cleanse(k, sizeof k);
    OPENSSL_cleanse(ck, sizeof ck);
    if (++s->message == PATTERN_MESSAGES[s->pattern])
        hs_finish(s);
    return (jint)text;
}
//#endregion

CRYPTO(jint, noiseRead)(JNIEnv *env, jclass cls, jlong state, jbyteArray msg, jint at, jint len, jbyteArray payload, jint off)
{
    if (len < 0)
        return -1;
    const size_t room = payload ? (size_t)((*env)->GetArrayLength(env, payload) - off) : 0;
    uint8_t *m = (uint8_t *)malloc((size_t)len + 1), *out = (uint8_t *)malloc(room + 1);
    if (!m || !out)
    {
        free(m);
        free(out);
        return -1;
    }
    (*env)->GetByteArrayRegion(env, msg, at, len, (jbyte *)m);
    const jint n = noise_read(state, m, len, out, room);
    if (0 < n)
        (*env)->SetByteArrayRegion(env, payload, off, n, (const jbyte *)out);
    OPENSSL_cleanse(out, room + 1);
    free(m);
    free(out);
    return n;
}

//#region The chain: whatever Java has chosen of it - TLS, the frames of a WebSocket, Noise - runs here, in one call a buffer each way
enum { OP_NOISE = 0, OP_MASK = 1, OP_TLS = 2, MAX_OPS = 8 };
enum { CHAIN_WS = 1, CHAIN_WS_CLIENT = 2, CHAIN_NOISE_ALIGNED = 4, CHAIN_IN_PIECES = 8 };
enum { MAX_PIECES = 8 };
enum { WS_NEW_FRAME = 0, WS_DATA = 1, WS_OTHER = 2 };

typedef struct
{
    int32_t kind, len;
    int64_t addr, a, b;
} ChainOp;

// Java reads and writes these where they lie, with no call: the offsets are in Chain.java.
typedef struct
{
    int64_t tls, rx_ctx, rx_n;                                                                   // 0, 8, 16
    int32_t flags, ws_state, ws_left, ws_mask, ws_mask_pos;                                      // 24, 28, 32, 36, 40
    int32_t raw_end, ws_end, noise_bytes, noise_count, tls_flags, ops, pieces;                   // 44 .. 68
    ChainOp op[MAX_OPS];                                                                         // 72, 32 each
    int32_t noise_end;                                                                           // 328
    int32_t piece[MAX_PIECES][2];                                                                // 332, from and to
} Chain;

_Static_assert(offsetof(Chain, ops) == 64 && offsetof(Chain, op) == 72 && offsetof(Chain, noise_end) == 328 && offsetof(Chain, piece) == 332 && sizeof(ChainOp) == 32, "the layout Chain.java knows");

JNIEXPORT jint JNICALL Java_org_unirail_Chain_linkSize(JNIEnv *env, jclass cls) { return (jint)sizeof(Chain); }

// The tls connection this chain runs over: its pointer is the same one Tls13 has.
static inline void chain_flags(Chain *c)
{
    const Conn *t = (const Conn *)(intptr_t)c->tls;
    c->tls_flags = t ? ((t->pending_key_update || t->pending_alert >= 0 ? 2 : 0) | (t->closed ? 1 : 0)) : 0;
}

// The mask of a frame on n bytes, the first of them at the place pos of the mask. Eight bytes at a time: the compiler widens it further.
static void ws_mask(uint8_t *p, size_t n, uint32_t m, size_t pos)
{
    const int r = (int)(pos & 3) * 8;
    const uint32_t k = r == 0 ? m : m >> r | m << (32 - r);
    const uint64_t w = (uint64_t)k | (uint64_t)k << 32;
    size_t j = 0;
    for (; j + 8 <= n; j += 8)
    {
        uint64_t v;
        memcpy(&v, p + j, 8);
        v ^= w;
        memcpy(p + j, &v, 8);
    }
    for (; j < n; j++)
        p[j] ^= (uint8_t)(k >> ((j & 3) * 8));
}

// What the layers of this buffer queued, in their order: the records of Noise, the mask of the frame, the record of TLS.
// The length of the TLS record, 0 - no TLS in it, -1 - failed.
JNIEXPORT jint JNICALL Java_org_unirail_Chain_tx(JNIEnv *env, jclass cls, jlong chain)
{
    Chain *c = (Chain *)(intptr_t)chain;
    int result = 0;
    for (int i = 0; i < c->ops; i++)
    {
        const ChainOp *o = &c->op[i];
        uint8_t *p = (uint8_t *)(intptr_t)o->addr;
        switch (o->kind)
        {
            case OP_NOISE:
            {
                uint64_t n = (uint64_t)o->b;
                uint8_t nonce[12];
                for (size_t at = 0; at < (size_t)o->len;)
                {
                    const size_t len = (size_t)p[at] | (size_t)p[at + 1] << 8;
                    noise_nonce(nonce, n++);
                    if (!aead_seal((const EVP_AEAD_CTX *)(intptr_t)o->a, nonce, p + at, 2, p + at + 2, len))
                        return -1;
                    at += 2 + len + TAG;
                }
                break;
            }
            case OP_MASK:
                ws_mask(p, (size_t)o->len, (uint32_t)o->a, 0);
                break;
            default:
                result = seal((Conn *)(intptr_t)c->tls, p, (size_t)o->len, APPLICATION_DATA, 0);
                if (result < 0)
                    return -1;
        }
    }
    c->ops = 0;
    chain_flags(c);
    return result;
}

// The payload down over the header in front of it, a few bytes: memmove on so close an overlap is slow. What is read goes out before the next
// read, and d < s: nothing not yet read is overwritten.
static void shift_down(uint8_t *d, const uint8_t *s, size_t n)
{
    size_t j = 0;
    for (; j + 32 <= n; j += 32)
    {
        uint64_t a, b, e, f;
        memcpy(&a, s + j, 8);
        memcpy(&b, s + j + 8, 8);
        memcpy(&e, s + j + 16, 8);
        memcpy(&f, s + j + 24, 8);
        memcpy(d + j, &a, 8);
        memcpy(d + j + 8, &b, 8);
        memcpy(d + j + 16, &e, 8);
        memcpy(d + j + 24, &f, 8);
    }
    for (; j < n; j++)
        d[j] = s[j];
}

// The same, up, over a header behind it: from the end down.
static void shift_up(uint8_t *d, const uint8_t *s, size_t n)
{
    size_t j = n;
    while (32 <= j)
    {
        j -= 32;
        uint64_t a, b, e, f;
        memcpy(&a, s + j, 8);
        memcpy(&b, s + j + 8, 8);
        memcpy(&e, s + j + 16, 8);
        memcpy(&f, s + j + 24, 8);
        memcpy(d + j, &a, 8);
        memcpy(d + j + 8, &b, 8);
        memcpy(d + j + 16, &e, 8);
        memcpy(d + j + 24, &f, 8);
    }
    while (0 < j)
    {
        j--;
        d[j] = s[j];
    }
}

// One run of the data, at the end of the list: what lies right behind the last one extends it, anything else starts a new one, with no byte
// moved. It joins the last one when the data must be in one piece, or when the list is full.
static void piece_add(int32_t (*list)[2], int32_t *count, uint8_t *base, size_t a, size_t n, int in_pieces)
{
    const int k = *count;
    if (k != 0)
    {
        const size_t end = (size_t)list[k - 1][1];
        if (end == a)
        {
            list[k - 1][1] = (int32_t)(end + n);
            return;
        }
        if (!in_pieces || k == MAX_PIECES)
        {
            shift_down(base + end, base + a, n);
            list[k - 1][1] = (int32_t)(end + n);
            return;
        }
    }
    list[k][0] = (int32_t)a;
    list[k][1] = (int32_t)(a + n);
    *count = k + 1;
}

// The frames of data in the runs `in`: each payload, unmasked, a run of its own where it lies. A frame cut by the end gives what it has and
// leaves its state for the next buffer. A header cut by the end of a run goes on in front of the next one. Anything else - a control frame, an
// empty one, what is not valid, a header cut by the end of the buffer - stops here, and what is left goes right behind the payload for the Java
// decoder, up to raw_end.
static void ws_strip(Chain *c, uint8_t *base, int32_t (*in)[2], int in_count, int in_pieces)
{
    const int client = (c->flags & CHAIN_WS_CLIENT) != 0;
    int k = 0;
    size_t p = 0, end = 0;
    int stopped = 0;
    for (; k < in_count && !stopped; k++)
    {
        p = (size_t)in[k][0];
        end = (size_t)in[k][1];
        if (c->ws_state == WS_DATA)
        {
            const size_t span = (size_t)c->ws_left < end - p ? (size_t)c->ws_left : end - p;
            if (!client && c->ws_mask != 0)
                ws_mask(base + p, span, (uint32_t)c->ws_mask, (size_t)c->ws_mask_pos);
            piece_add(c->piece, &c->pieces, base, p, span, in_pieces);
            c->ws_mask_pos = (int32_t)(((size_t)c->ws_mask_pos + span) & 3);
            c->ws_left -= (int32_t)span;
            p += span;
            if (c->ws_left == 0)
                c->ws_state = WS_NEW_FRAME;
        }
        while (c->ws_state == WS_NEW_FRAME && p != end)
        {
            const size_t have = end - p;
            size_t header = 0;
            uint64_t len = 0;
            uint32_t m = 0;
            if (have >= 2)
            {
                const uint8_t b0 = base[p], b1 = base[p + 1];
                const int opcode = b0 & 0x0F;
                if ((b0 & 0x70) != 0 || opcode > 2 || ((b1 & 0x80) == 0) != client)
                {
                    stopped = 1;
                    break;
                }
                len = b1 & 0x7F;
                const size_t need = (len == 126 ? 4 : len == 127 ? 10 : 2) + (client ? 0 : 4);
                if (have >= need)
                {
                    header = 2;
                    if (len == 126)
                    {
                        len = (uint64_t)base[p + 2] << 8 | base[p + 3];
                        header = 4;
                    }
                    else if (len == 127)
                    {
                        len = 0;
                        for (int j = 0; j < 8; j++)
                            len = len << 8 | base[p + 2 + (size_t)j];
                        header = 10;
                    }
                    if (len == 0 || len > 0x7FFFFFFF)
                    {
                        stopped = 1;
                        break;
                    }
                    if (!client)
                    {
                        m = (uint32_t)base[p + header] | (uint32_t)base[p + header + 1] << 8 | (uint32_t)base[p + header + 2] << 16 | (uint32_t)base[p + header + 3] << 24;
                        header += 4;
                    }
                }
            }
            if (header == 0)
            { //a header cut: in front of the next run, or that is all there is
                if (k + 1 == in_count)
                {
                    stopped = 1;
                    break;
                }
                shift_up(base + in[k + 1][0] - have, base + p, have);
                in[k + 1][0] -= (int32_t)have;
                p = end;
                break;
            }
            const size_t span = len < have - header ? (size_t)len : have - header;
            piece_add(c->piece, &c->pieces, base, p + header, span, in_pieces);
            if (m != 0)
                ws_mask(base + c->piece[c->pieces - 1][1] - span, span, m, 0);
            p += header + span;
            if (span < len)
            {
                c->ws_state = WS_DATA;
                c->ws_left = (int32_t)(len - span);
                c->ws_mask = (int32_t)m;
                c->ws_mask_pos = (int32_t)(span & 3);
            }
        }
    }
    if (c->pieces == 0)
        piece_add(c->piece, &c->pieces, base, stopped ? p : in_count != 0 ? (size_t)in[0][0] : 0, 0, in_pieces);
    size_t out = (size_t)c->piece[c->pieces - 1][1];
    c->ws_end = (int32_t)out;
    if (stopped)
    {
        for (k--;; )
        { //the run it stopped in, and the ones behind it
            const size_t n = end - p;
            if (n != 0 && out != p)
                shift_down(base + out, base + p, n);
            out += n;
            if (++k == in_count)
                break;
            p = (size_t)in[k][0];
            end = (size_t)in[k][1];
        }
    }
    c->raw_end = (int32_t)out;
}

// The records of Noise in the runs, opened where they lie. One cut by the end of a run moves, only it, in front of the next run.
static void noise_open(Chain *c, uint8_t *base)
{
    uint8_t nonce[12];
    uint64_t n = (uint64_t)c->rx_n;
    size_t opened = 0;
    c->noise_end = -1;
    for (int i = 0; i < c->pieces; i++)
    {
        size_t p = (size_t)c->piece[i][0];
        const size_t end = (size_t)c->piece[i][1];
        for (;;)
        {
            const size_t have = end - p;
            const size_t len = have < 2 ? 0 : (size_t)base[p] | (size_t)base[p + 1] << 8;
            if (have >= 2 && (len == 0 || 16384 < len))
            { // a length no record has: the stream finds it out as it reads on
                c->noise_bytes = (int32_t)opened;
                c->rx_n = (int64_t)n;
                return;
            }
            if (have >= 2 && have >= 2 + len + TAG)
            {
                noise_nonce(nonce, n);
                if (!aead_open((const EVP_AEAD_CTX *)(intptr_t)c->rx_ctx, nonce, base + p, 2, base + p + 2, len))
                { // the same: this record fails again there, and ends the stream
                    c->noise_bytes = (int32_t)opened;
                    c->rx_n = (int64_t)n;
                    return;
                }
                n++;
                c->noise_count++;
                opened += 2 + len + TAG;
                p += 2 + len + TAG;
                continue;
            }
            if (have != 0 && i + 1 < c->pieces)
            { // goes on in the next run
                shift_up(base + c->piece[i + 1][0] - have, base + p, have);
                c->piece[i + 1][0] -= (int32_t)have;
                c->piece[i][1] = (int32_t)p;
            }
            else if (i + 1 == c->pieces)
                c->noise_end = (int32_t)p; // waits for the next read
            break;
        }
    }
    c->noise_bytes = (int32_t)opened;
    c->rx_n = (int64_t)n;
}

// What came from the socket, at [at, limit): TLS opened, the frames cut, the records of Noise opened - in this one call, nothing moved that does
// not have to be. Then the data are the runs in c->piece, ws_end the end of the last; up to raw_end behind it what is left for the Java decoder,
// and from consumed_end on a TLS record not all here. [0, at) is the first run: the part of a record carried over, or what the framing left.
// consumed_end << 42 | raw_end << 21 | ws_end, the buffer under 2 MB; -1: TLS is over.
static jlong chain_rx(Chain *c, uint8_t *base, jint at, jint limit)
{
    const int in_pieces = (c->flags & CHAIN_IN_PIECES) != 0;
    const int frames = (c->flags & CHAIN_WS) != 0 && c->ws_state != WS_OTHER;
    int32_t in[MAX_PIECES][2];
    int32_t in_count = 0;
    size_t from = (size_t)limit;
    c->noise_bytes = c->noise_count = c->pieces = 0;
    c->noise_end = -1;
    if (at != 0 || !in_pieces)
        piece_add(c->piece, &c->pieces, base, 0, (size_t)at, in_pieces);
    if (c->tls)
    {
        Conn *t = (Conn *)(intptr_t)c->tls;
        from = (size_t)at;
        for (;;)
        {
            const jlong r = open_record(t, base + from, (size_t)limit - from);
            if (r < 0)
                return -1;
            if (r == 0)
                break;
            const size_t total = (size_t)(r >> 32), data = (size_t)(r & 0xFFFF);
            if (data != 0)
            {
                if (frames)
                    piece_add(in, &in_count, base, from + HEADER, data, 1);
                else
                    piece_add(c->piece, &c->pieces, base, from + HEADER, data, in_pieces);
            }
            from += total;
            if (t->closed)
            {
                from = (size_t)limit;
                break;
            }
        }
        chain_flags(c);
    }
    else if (frames)
    {
        in[0][0] = at;
        in[0][1] = limit;
        in_count = 1;
    }
    else
        piece_add(c->piece, &c->pieces, base, (size_t)at, (size_t)limit - (size_t)at, in_pieces);
    if (frames)
        ws_strip(c, base, in, in_count, in_pieces);
    else
    {
        if (c->pieces == 0)
            piece_add(c->piece, &c->pieces, base, 0, 0, in_pieces);
        c->raw_end = c->ws_end = c->piece[c->pieces - 1][1];
    }
    if ((c->flags & CHAIN_NOISE_ALIGNED) != 0 && c->rx_ctx != 0)
    {
        const int64_t first = c->rx_n;
        noise_open(c, base);
        c->rx_n = first; // Java keeps the number: it counts what it is told were opened
    }
    int kept = 0;
    for (int i = 0; i < c->pieces; i++)
        if (c->piece[i][0] != c->piece[i][1] || i + 1 == c->pieces)
        {
            c->piece[kept][0] = c->piece[i][0];
            c->piece[kept][1] = c->piece[i][1];
            kept++;
        }
    c->pieces = kept;
    return (jlong)from << 42 | (jlong)c->raw_end << 21 | (jlong)c->ws_end;
}

JNIEXPORT jlong JNICALL Java_org_unirail_Chain_rx(JNIEnv *env, jclass cls, jlong chain, jobject buffer, jint at, jint limit)
{
    return chain_rx((Chain *)(intptr_t)chain, (uint8_t *)(*env)->GetDirectBufferAddress(env, buffer), at, limit);
}

// A pack on its own, E6 and E7 together: signed by its author, then sealed under the key of the pair, in one call. In place: the text,
// then the 64 bytes of the signature, then the tag; the header in front is authenticated. secret, pub: 0 - not signed.
CRYPTO(jint, packSeal)(JNIEnv *env, jclass cls, jlong ctx, jlong n, jlong secret, jlong address, jint header, jint len)
{
    uint8_t *p = ADDR(uint8_t, address), *text = p + header, nonce[12];
    size_t all = (size_t)len;
    if (secret != 0)
    {
        if (!ED25519_sign(text + len, text, (size_t)len, ADDR(const uint8_t, secret)))
            return -1;
        all += 64;
    }
    noise_nonce(nonce, (uint64_t)n);
    if (ctx != 0 && !aead_seal(ADDR(EVP_AEAD_CTX, ctx), nonce, p, (size_t)header, text, all))
        return -1;
    return (jint)((size_t)header + all + (ctx != 0 ? TAG : 0));
}

// The length of the text; -1 - forged, or not signed by the one it must be.
CRYPTO(jint, packOpen)(JNIEnv *env, jclass cls, jlong ctx, jlong n, jlong pub, jlong address, jint header, jint total)
{
    uint8_t *p = ADDR(uint8_t, address), *text = p + header, nonce[12];
    size_t all = (size_t)total - (size_t)header;
    if (ctx != 0)
    {
        if (all < TAG)
            return -1;
        all -= TAG;
        noise_nonce(nonce, (uint64_t)n);
        if (!aead_open(ADDR(EVP_AEAD_CTX, ctx), nonce, p, (size_t)header, text, all))
            return -1;
    }
    if (pub != 0)
    {
        if (all < 64)
            return -1;
        all -= 64;
        if (!ED25519_verify(text, all, text + all, ADDR(const uint8_t, pub)))
            return -1;
    }
    return (jint)all;
}
//#endregion

//#region For a runtime with no JNI ( C# ): plain C over the same code. What takes no JNI object in the functions above goes straight through them.
#define ADHOC(ret, name) JNIEXPORT ret JNICALL adhoc_##name

ADHOC(jint, abi)(void) { return Java_org_unirail_crypto_Native_abi(NULL, NULL); }

ADHOC(jint, aead_size)(void) { return (jint)sizeof(EVP_AEAD_CTX); }

ADHOC(jint, aead_init)(jint kind, void *ctx, const uint8_t *key, jint key_len)
{
    const EVP_AEAD *aead = kind == 0 ? EVP_aead_chacha20_poly1305() : kind == 1 ? EVP_aead_aes_128_gcm() : kind == 2 ? EVP_aead_aes_256_gcm() : NULL;
    if (!aead || (size_t)key_len != EVP_AEAD_key_length(aead))
        return 0;
    const int ok = EVP_AEAD_CTX_init((EVP_AEAD_CTX *)ctx, aead, key, (size_t)key_len, TAG, NULL);
    ERR_clear_error();
    return ok;
}

ADHOC(jint, seal)(jlong ctx, jlong n, jlong ad, jint ad_len, jlong text, jint len) { return Java_org_unirail_crypto_Crypto_seal(NULL, NULL, ctx, n, ad, ad_len, text, len); }

ADHOC(jint, open)(jlong ctx, jlong n, jlong ad, jint ad_len, jlong text, jint len) { return Java_org_unirail_crypto_Crypto_open(NULL, NULL, ctx, n, ad, ad_len, text, len); }

ADHOC(jint, seal_nonce)(jlong ctx, const uint8_t *nonce, const uint8_t *ad, jint ad_len, uint8_t *text, jint len) { return aead_seal(ADDR(EVP_AEAD_CTX, ctx), nonce, ad, (size_t)ad_len, text, (size_t)len); }

ADHOC(jint, open_nonce)(jlong ctx, const uint8_t *nonce, const uint8_t *ad, jint ad_len, uint8_t *text, jint len) { return aead_open(ADDR(EVP_AEAD_CTX, ctx), nonce, ad, (size_t)ad_len, text, (size_t)len); }

ADHOC(jlong, seal_records)(jlong ctx, jlong n, jlong address, jint bytes) { return Java_org_unirail_crypto_Crypto_sealRecords(NULL, NULL, ctx, n, address, bytes); }

ADHOC(jlong, open_records)(jlong ctx, jlong n, jlong address, jint have, jint max) { return Java_org_unirail_crypto_Crypto_openRecords(NULL, NULL, ctx, n, address, have, max); }

ADHOC(jint, stream_size)(void) { return (jint)sizeof(Stream); }

ADHOC(void, stream_xor)(jlong state, jlong address, jint len) { Java_org_unirail_crypto_Crypto_streamXor(NULL, NULL, state, address, len); }

ADHOC(jint, x25519)(uint8_t *shared, const uint8_t *secret, const uint8_t *peer) { return X25519(shared, secret, peer); }

ADHOC(void, x25519_public)(uint8_t *pub, const uint8_t *secret) { X25519_public_from_private(pub, secret); }

ADHOC(void, x25519_keypair)(uint8_t *secret, uint8_t *pub) { X25519_keypair(pub, secret); }

ADHOC(jint, noise_size)(void) { return (jint)sizeof(Hs); }

ADHOC(jint, noise_tx)(void) { return (jint)offsetof(Hs, tx); }

ADHOC(jint, noise_rx)(void) { return (jint)offsetof(Hs, rx); }

ADHOC(void, noise_init)(jlong state, jint pattern, jint initiator, const uint8_t *prologue, jint prologue_len, const uint8_t *static_secret, const uint8_t *static_public, const uint8_t *peer, const uint8_t *ephemeral) { noise_init(state, pattern, initiator, prologue, (size_t)prologue_len, static_secret, static_public, peer, ephemeral); }

ADHOC(jint, noise_write)(jlong state, uint8_t *dst, jint cap, const uint8_t *payload, jint len) { return noise_write(state, dst, (size_t)cap, payload, len); }

ADHOC(jint, noise_read)(jlong state, const uint8_t *msg, jint len, uint8_t *payload, jint room) { return noise_read(state, msg, len, payload, (size_t)room); }

ADHOC(jlong, tls_context)(void) { return Java_org_unirail_crypto_Tls13_newContext(NULL, NULL); }

ADHOC(jlong, tls_server_context)(const void *chain, jint chain_len, const void *key, jint key_len) { return (jlong)(intptr_t)server_context(chain, chain_len, key, key_len); }

ADHOC(void, tls_context_free)(jlong ctx) { SSL_CTX_free((SSL_CTX *)(intptr_t)ctx); }

ADHOC(jlong, tls_server)(jlong ctx) { return Java_org_unirail_crypto_Tls13_newServerConnection(NULL, NULL, ctx); }

ADHOC(jlong, tls_client)(jlong ctx, const char *host, const uint8_t *alpn, jint alpn_len, int (*verify)(void *, int, const uint8_t **, const int *), void *verify_ctx)
{
    const jlong conn = client_connection(ctx, host, alpn, (size_t)alpn_len);
    if (conn)
    {
        ((Conn *)(intptr_t)conn)->verify_fn = verify;
        ((Conn *)(intptr_t)conn)->verify_ctx = verify_ctx;
    }
    return conn;
}

ADHOC(jlong, tls_handshake)(jlong conn, jlong in, jint in_len, jlong out, jint out_cap) { return Java_org_unirail_crypto_Tls13_handshake(NULL, NULL, conn, in, in_len, out, out_cap); }

ADHOC(void, tls_tx_limit)(jlong conn, jlong records) { Java_org_unirail_crypto_Tls13_txLimit(NULL, NULL, conn, records); }

ADHOC(jint, tls_control)(jlong conn, jlong record) { return Java_org_unirail_crypto_Tls13_control(NULL, NULL, conn, record); }

ADHOC(void, tls_close_notify)(jlong conn) { Java_org_unirail_crypto_Tls13_closeNotify(NULL, NULL, conn); }

ADHOC(const char *, tls_error)(jlong conn)
{
    const Conn *c = (const Conn *)(intptr_t)conn;
    return c->error ? c->error : "unknown";
}

ADHOC(void, tls_free)(jlong conn) { Java_org_unirail_crypto_Tls13_free(NULL, NULL, conn); }

ADHOC(jint, chain_size)(void) { return (jint)sizeof(Chain); }

ADHOC(jint, chain_tx)(jlong chain) { return Java_org_unirail_Chain_tx(NULL, NULL, chain); }

ADHOC(jlong, chain_rx)(jlong chain, uint8_t *base, jint at, jint limit) { return chain_rx((Chain *)(intptr_t)chain, base, at, limit); }

ADHOC(void, ed25519_keypair)(uint8_t *secret, uint8_t *pub, const uint8_t *seed)
{
    if (seed)
        ED25519_keypair_from_seed(pub, secret, seed);
    else
        ED25519_keypair(pub, secret);
}

ADHOC(jint, ed25519_sign)(uint8_t *signature, const uint8_t *secret, const uint8_t *message, jlong len) { return ED25519_sign(signature, message, (size_t)len, secret); }

ADHOC(jint, ed25519_verify)(const uint8_t *signature, const uint8_t *pub, const uint8_t *message, jlong len) { return ED25519_verify(message, (size_t)len, signature, pub); }

ADHOC(jint, pair_key)(uint8_t *key, uint8_t *iv, int32_t *id, const uint8_t *secret, const uint8_t *their, const uint8_t *label, jint label_len) { return pair_key(key, iv, id, secret, their, label, (size_t)label_len); }

ADHOC(jint, pack_seal)(jlong ctx, jlong n, jlong secret, jlong address, jint header, jint len) { return Java_org_unirail_crypto_Crypto_packSeal(NULL, NULL, ctx, n, secret, address, header, len); }

ADHOC(jint, pack_open)(jlong ctx, jlong n, jlong pub, jlong address, jint header, jint total) { return Java_org_unirail_crypto_Crypto_packOpen(NULL, NULL, ctx, n, pub, address, header, total); }
//#endregion
