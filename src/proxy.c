/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "proxy.h"
#include "crypto.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <time.h>

/* Reject WebSocket frames larger than this (a hostile/MITM server could
 * otherwise request a huge g_malloc and abort the process). */
#define WS_MAX_FRAME (1u << 20)

/* MTProto obfuscated-handshake layout. */
#define HANDSHAKE_LEN 64
#define SKIP_LEN       8
#define PREKEY_LEN    32
#define IV_LEN        16
#define PROTO_TAG_POS 56
#define DC_IDX_POS    60

#define PROTO_ABRIDGED_INT            0xEFEFEFEFu
#define PROTO_INTERMEDIATE_INT        0xEEEEEEEEu
#define PROTO_PADDED_INTERMEDIATE_INT 0xDDDDDDDDu

#define READ_CHUNK 65536

static const unsigned char ZERO_64[64] = { 0 };

/* Default TCP/CF fallback target IP per DC. */
static const char *
dc_default_ip (int dc)
{
    switch (dc) {
        case 1:   return "149.154.175.50";
        case 2:   return "149.154.167.51";
        case 3:   return "149.154.175.100";
        case 4:   return "149.154.167.91";
        case 5:   return "149.154.171.5";
        case 203: return "91.105.192.100";
    }
    return NULL;
}

/* Built-in Cloudflare-proxied base domains, used when no user domains are set. */
static const char *CF_DEFAULT_DOMAINS[] = {
    "pclead.co.uk", "offshor.co.uk", "cakeisalie.co.uk", "noskomnadzor.co.uk",
    "lovetrue.co.uk", "sorokdva.co.uk", "pyatdesyatdva.co.uk", "kartoshka.co.uk",
    "sorokodin.co.uk", "pyatdesyatodin.co.uk",
};

/* ============================ small helpers ============================ */

static void
sha256 (const unsigned char *data, size_t len, unsigned char out[32])
{
    unsigned int mdlen = 32;
    EVP_Digest (data, len, out, &mdlen, EVP_sha256 (), NULL);
}

static void
reverse_into (unsigned char *dst, const unsigned char *src, int n)
{
    for (int i = 0; i < n; i++)
        dst[i] = src[n - 1 - i];
}

/* Read exactly n bytes from a plain fd; FALSE on EOF/error. */
static gboolean
fd_read_exact (int fd, unsigned char *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv (fd, buf + got, n - got, 0);
        if (r <= 0) {
            if (r < 0 && errno == EINTR)
                continue;
            return FALSE;
        }
        got += (size_t) r;
    }
    return TRUE;
}

static gboolean
fd_write_all (int fd, const unsigned char *buf, size_t n)
{
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = send (fd, buf + sent, n - sent, MSG_NOSIGNAL);
        if (w <= 0) {
            if (w < 0 && errno == EINTR)
                continue;
            return FALSE;
        }
        sent += (size_t) w;
    }
    return TRUE;
}

/* ============================ crypto context ============================ */

typedef struct {
    TgwsAesCtr *clt_dec;  /* decrypt FROM client */
    TgwsAesCtr *clt_enc;  /* encrypt TO client */
    TgwsAesCtr *tg_enc;   /* encrypt TO telegram */
    TgwsAesCtr *tg_dec;   /* decrypt FROM telegram */
} CryptoCtx;

static void
crypto_ctx_clear (CryptoCtx *c)
{
    if (c->clt_dec) tgws_aesctr_free (c->clt_dec);
    if (c->clt_enc) tgws_aesctr_free (c->clt_enc);
    if (c->tg_enc)  tgws_aesctr_free (c->tg_enc);
    if (c->tg_dec)  tgws_aesctr_free (c->tg_dec);
    memset (c, 0, sizeof (*c));
}

/* Parse the 64-byte client init. Returns FALSE on wrong secret / bad proto. */
static gboolean
try_handshake (const unsigned char *handshake, const unsigned char *secret,
               int *out_dc, gboolean *out_media, unsigned char out_proto[4],
               unsigned char out_prekey_iv[48])
{
    const unsigned char *prekey = handshake + SKIP_LEN;        /* [8:40]  */
    const unsigned char *iv     = handshake + SKIP_LEN + PREKEY_LEN; /* [40:56] */

    unsigned char keymat[PREKEY_LEN + 16];
    memcpy (keymat, prekey, PREKEY_LEN);
    memcpy (keymat + PREKEY_LEN, secret, 16);
    unsigned char key[32];
    sha256 (keymat, PREKEY_LEN + 16, key);

    unsigned char dec[HANDSHAKE_LEN];
    TgwsAesCtr *c = tgws_aesctr_new (key, iv);
    tgws_aesctr_update (c, handshake, dec, HANDSHAKE_LEN);
    tgws_aesctr_free (c);

    unsigned char v = dec[PROTO_TAG_POS];
    if (v != 0xef && v != 0xee && v != 0xdd)
        return FALSE;
    if (dec[PROTO_TAG_POS + 1] != v || dec[PROTO_TAG_POS + 2] != v ||
        dec[PROTO_TAG_POS + 3] != v)
        return FALSE;

    gint16 dc_idx = (gint16) (dec[DC_IDX_POS] | (dec[DC_IDX_POS + 1] << 8));
    *out_dc = (dc_idx < 0) ? -dc_idx : dc_idx;
    *out_media = dc_idx < 0;
    memcpy (out_proto, dec + PROTO_TAG_POS, 4);
    memcpy (out_prekey_iv, handshake + SKIP_LEN, 48);  /* plaintext [8:56] */
    return TRUE;
}

/* Build the obfuscated 64-byte init sent to Telegram. */
static void
generate_relay_init (const unsigned char proto_tag[4], gint16 dc_idx,
                     unsigned char out[HANDSHAKE_LEN])
{
    static const unsigned char reserved_starts[6][4] = {
        { 0x48, 0x45, 0x41, 0x44 },   /* HEAD */
        { 0x50, 0x4f, 0x53, 0x54 },   /* POST */
        { 0x47, 0x45, 0x54, 0x20 },   /* "GET " */
        { 0xee, 0xee, 0xee, 0xee },
        { 0xdd, 0xdd, 0xdd, 0xdd },
        { 0x16, 0x03, 0x01, 0x02 },
    };
    unsigned char rnd[HANDSHAKE_LEN];
    for (;;) {
        RAND_bytes (rnd, HANDSHAKE_LEN);
        if (rnd[0] == 0xef)
            continue;
        gboolean bad = FALSE;
        for (int i = 0; i < 6; i++)
            if (memcmp (rnd, reserved_starts[i], 4) == 0) { bad = TRUE; break; }
        if (bad)
            continue;
        if (rnd[4] == 0 && rnd[5] == 0 && rnd[6] == 0 && rnd[7] == 0)
            continue;
        break;
    }

    const unsigned char *enc_key = rnd + SKIP_LEN;                 /* [8:40]  */
    const unsigned char *enc_iv  = rnd + SKIP_LEN + PREKEY_LEN;    /* [40:56] */

    unsigned char enc_full[HANDSHAKE_LEN];
    TgwsAesCtr *c = tgws_aesctr_new (enc_key, enc_iv);
    tgws_aesctr_update (c, rnd, enc_full, HANDSHAKE_LEN);
    tgws_aesctr_free (c);

    guint16 u = (guint16) dc_idx;
    unsigned char tail_plain[8];
    memcpy (tail_plain, proto_tag, 4);
    tail_plain[4] = (unsigned char) (u & 0xff);
    tail_plain[5] = (unsigned char) ((u >> 8) & 0xff);
    RAND_bytes (tail_plain + 6, 2);

    memcpy (out, rnd, HANDSHAKE_LEN);
    for (int i = 0; i < 8; i++) {
        unsigned char ks = enc_full[PROTO_TAG_POS + i] ^ rnd[PROTO_TAG_POS + i];
        out[PROTO_TAG_POS + i] = tail_plain[i] ^ ks;
    }
}

static void
build_crypto_ctx (const unsigned char prekey_iv[48], const unsigned char *secret,
                  const unsigned char relay_init[HANDSHAKE_LEN], CryptoCtx *ctx)
{
    unsigned char tmp[64];
    unsigned char keymat[PREKEY_LEN + 16];
    unsigned char key[32];

    /* client side: key = SHA256(prekey + secret), iv = prekey_iv[32:48] */
    memcpy (keymat, prekey_iv, PREKEY_LEN);
    memcpy (keymat + PREKEY_LEN, secret, 16);
    sha256 (keymat, PREKEY_LEN + 16, key);
    ctx->clt_dec = tgws_aesctr_new (key, prekey_iv + PREKEY_LEN);

    unsigned char rev48[48];
    reverse_into (rev48, prekey_iv, 48);
    memcpy (keymat, rev48, PREKEY_LEN);
    memcpy (keymat + PREKEY_LEN, secret, 16);
    sha256 (keymat, PREKEY_LEN + 16, key);
    ctx->clt_enc = tgws_aesctr_new (key, rev48 + PREKEY_LEN);

    /* fast-forward the client decryptor past the 64-byte init */
    tgws_aesctr_update (ctx->clt_dec, ZERO_64, tmp, 64);

    /* relay (telegram) side: raw key, no secret hash */
    ctx->tg_enc = tgws_aesctr_new (relay_init + SKIP_LEN,
                                   relay_init + SKIP_LEN + PREKEY_LEN);
    reverse_into (rev48, relay_init + SKIP_LEN, 48);  /* reverse([8:56]) */
    ctx->tg_dec = tgws_aesctr_new (rev48, rev48 + PREKEY_LEN);

    tgws_aesctr_update (ctx->tg_enc, ZERO_64, tmp, 64);
}

/* ============================ MsgSplitter ============================ */

typedef struct {
    TgwsAesCtr *dec;
    guint32     proto;
    GByteArray *cipher_buf;
    GByteArray *plain_buf;
    gboolean    disabled;
} MsgSplitter;

static MsgSplitter *
splitter_new (const unsigned char relay_init[HANDSHAKE_LEN], guint32 proto)
{
    MsgSplitter *s = g_new0 (MsgSplitter, 1);
    s->dec = tgws_aesctr_new (relay_init + SKIP_LEN,
                              relay_init + SKIP_LEN + PREKEY_LEN);
    unsigned char tmp[64];
    tgws_aesctr_update (s->dec, ZERO_64, tmp, 64);   /* fast-forward */
    s->proto = proto;
    s->cipher_buf = g_byte_array_new ();
    s->plain_buf = g_byte_array_new ();
    return s;
}

static void
splitter_free (MsgSplitter *s)
{
    if (!s) return;
    if (s->dec) tgws_aesctr_free (s->dec);
    g_byte_array_free (s->cipher_buf, TRUE);
    g_byte_array_free (s->plain_buf, TRUE);
    g_free (s);
}

/* -1 = need more; 0 = unknown proto (stop splitting); >0 = packet length. */
static int
splitter_next_len (MsgSplitter *s, int offset, int avail)
{
    if (avail <= 0)
        return -1;
    const guint8 *p = s->plain_buf->data;
    if (s->proto == PROTO_ABRIDGED_INT) {
        guint8 first = p[offset];
        int payload_len, header_len;
        if (first == 0x7F || first == 0xFF) {
            if (avail < 4) return -1;
            payload_len = (p[offset + 1] | (p[offset + 2] << 8)
                           | (p[offset + 3] << 16)) * 4;
            header_len = 4;
        } else {
            payload_len = (first & 0x7F) * 4;
            header_len = 1;
        }
        if (payload_len <= 0) return 0;
        int packet_len = header_len + payload_len;
        if (avail < packet_len) return -1;
        return packet_len;
    }
    if (s->proto == PROTO_INTERMEDIATE_INT ||
        s->proto == PROTO_PADDED_INTERMEDIATE_INT) {
        if (avail < 4) return -1;
        guint32 payload_len = ((guint32) p[offset]
                               | ((guint32) p[offset + 1] << 8)
                               | ((guint32) p[offset + 2] << 16)
                               | ((guint32) p[offset + 3] << 24)) & 0x7FFFFFFFu;
        if (payload_len == 0) return 0;
        int packet_len = 4 + (int) payload_len;
        if (avail < packet_len) return -1;
        return packet_len;
    }
    return 0;
}

/* Split a re-encrypted (to-telegram) chunk into MTProto packets; each emitted
 * packet is appended to @out as a GBytes (caller unrefs). */
static void
splitter_split (MsgSplitter *s, const unsigned char *chunk, int len,
                GPtrArray *out)
{
    if (len == 0)
        return;
    if (s->disabled) {
        g_ptr_array_add (out, g_bytes_new (chunk, len));
        return;
    }
    g_byte_array_append (s->cipher_buf, chunk, len);

    unsigned char *dp = g_malloc (len);
    tgws_aesctr_update (s->dec, chunk, dp, len);
    g_byte_array_append (s->plain_buf, dp, len);
    g_free (dp);

    int offset = 0;
    int buf_len = (int) s->cipher_buf->len;
    while (offset < buf_len) {
        int plen = splitter_next_len (s, offset, buf_len - offset);
        if (plen == -1)
            break;
        if (plen <= 0) {  /* unknown proto: emit the rest, stop splitting */
            g_ptr_array_add (out, g_bytes_new (s->cipher_buf->data + offset,
                                               buf_len - offset));
            offset = buf_len;
            s->disabled = TRUE;
            break;
        }
        g_ptr_array_add (out, g_bytes_new (s->cipher_buf->data + offset, plen));
        offset += plen;
    }
    if (offset > 0) {
        g_byte_array_remove_range (s->cipher_buf, 0, offset);
        g_byte_array_remove_range (s->plain_buf, 0, offset);
    }
}

static GBytes *
splitter_flush (MsgSplitter *s)
{
    if (s->cipher_buf->len == 0)
        return NULL;
    GBytes *tail = g_bytes_new (s->cipher_buf->data, s->cipher_buf->len);
    g_byte_array_set_size (s->cipher_buf, 0);
    g_byte_array_set_size (s->plain_buf, 0);
    return tail;
}

/* ============================ TLS + WebSocket ============================ */

static SSL_CTX *g_ssl_ctx = NULL;

/* Load the system CA trust at runtime, independent of the TLS library and
 * distro: $SSL_CERT_FILE first, then the well-known bundle locations across
 * Linux distros, finally the library's own defaults ($SSL_CERT_DIR / built-in).
 * The library default alone is unreliable (e.g. LibreSSL points at a path that
 * may not exist). On Windows/macOS this needs a native cert-store backend. */
static void
load_system_ca (SSL_CTX *ctx)
{
    const char *env_ca = g_getenv ("SSL_CERT_FILE");
    if (env_ca != NULL && *env_ca != '\0' &&
        SSL_CTX_load_verify_locations (ctx, env_ca, NULL) == 1)
        return;

    static const char *bundles[] = {
        "/etc/ssl/certs/ca-certificates.crt",                 /* Debian/Ubuntu/Arch/Flatpak */
        "/etc/pki/tls/certs/ca-bundle.crt",                   /* Fedora/RHEL */
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",  /* CentOS/RHEL */
        "/etc/pki/tls/cert.pem",                              /* ALT */
        "/var/lib/ssl/cert.pem",                              /* ALT (OpenSSL dir) */
        "/etc/ssl/cert.pem",                                  /* Alpine / *BSD / macOS */
        NULL
    };
    for (int i = 0; bundles[i] != NULL; i++)
        if (g_file_test (bundles[i], G_FILE_TEST_EXISTS) &&
            SSL_CTX_load_verify_locations (ctx, bundles[i], NULL) == 1)
            return;

    SSL_CTX_set_default_verify_paths (ctx);
}

static void
ensure_ssl_ctx (void)
{
    static gsize once = 0;
    if (g_once_init_enter (&once)) {
        SSL_library_init ();
        g_ssl_ctx = SSL_CTX_new (TLS_client_method ());
        /* Default off; per-connection SSL_VERIFY_PEER is enabled for real
         * domains (CF), kept off for the direct DC-IP path (SNI != cert). */
        SSL_CTX_set_verify (g_ssl_ctx, SSL_VERIFY_NONE, NULL);
        load_system_ca (g_ssl_ctx);
        SSL_CTX_set_min_proto_version (g_ssl_ctx, TLS1_2_VERSION);
        g_once_init_leave (&once, 1);
    }
}

typedef struct {
    SSL *ssl;
    int  fd;
    gboolean closed;
} WsConn;

static gboolean ssl_write_all (SSL *ssl, const unsigned char *buf, size_t n);

/* TCP connect to host:port (host may be an IP or a DNS name), TCP_NODELAY. */
static int
tcp_connect_host (const char *host, int port)
{
    struct addrinfo hints, *res = NULL;
    memset (&hints, 0, sizeof (hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char portstr[8];
    g_snprintf (portstr, sizeof (portstr), "%d", port);
    if (getaddrinfo (host, portstr, &hints, &res) != 0)
        return -1;
    int fd = -1;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket (ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0)
            continue;
        if (connect (fd, ai->ai_addr, ai->ai_addrlen) == 0)
            break;
        close (fd);
        fd = -1;
    }
    freeaddrinfo (res);
    if (fd >= 0) {
        int one = 1;
        setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof (one));
    }
    return fd;
}

/* TLS to connect_host:443 with SNI=sni, then the WebSocket upgrade for @path
 * with Host=sni. connect_host may be an IP or DNS name. When @verify is set the
 * peer certificate and hostname (sni) are checked; otherwise no verification
 * (used for the direct DC-IP path, where the cert won't match the IP).
 * NULL on any failure. */
static WsConn *
ws_connect_host (const char *connect_host, const char *sni, const char *path,
                 gboolean verify)
{
    ensure_ssl_ctx ();

    int fd = tcp_connect_host (connect_host, 443);
    if (fd < 0)
        return NULL;

    SSL *ssl = SSL_new (g_ssl_ctx);
    SSL_set_fd (ssl, fd);
    SSL_set_tlsext_host_name (ssl, sni);        /* SNI */
    if (verify) {
        SSL_set_verify (ssl, SSL_VERIFY_PEER, NULL);
        SSL_set1_host (ssl, sni);               /* hostname must match cert */
    }
    if (SSL_connect (ssl) != 1) {
        SSL_free (ssl);
        close (fd);
        return NULL;
    }

    WsConn *ws = g_new0 (WsConn, 1);
    ws->ssl = ssl;
    ws->fd = fd;

    /* WebSocket upgrade. The Sec-WebSocket-Key value is cosmetic for us. */
    unsigned char keyraw[16];
    RAND_bytes (keyraw, 16);
    gchar *key_b64 = g_base64_encode (keyraw, 16);
    gchar *req = g_strdup_printf (
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Protocol: binary\r\n\r\n",
        path, sni, key_b64);
    gboolean wok = ssl_write_all (ssl, (const unsigned char *) req, strlen (req));
    g_free (key_b64);
    g_free (req);
    if (!wok)
        goto fail;

    /* Read the response headers up to the blank line (byte at a time; small). */
    GString *resp = g_string_new (NULL);
    for (;;) {
        unsigned char ch;
        int r = SSL_read (ssl, &ch, 1);
        if (r <= 0)
            break;
        g_string_append_c (resp, ch);
        if (resp->len >= 4 &&
            memcmp (resp->str + resp->len - 4, "\r\n\r\n", 4) == 0)
            break;
        if (resp->len > 8192)
            break;
    }
    gboolean upgraded = (strstr (resp->str, " 101 ") != NULL) ||
                        (g_str_has_prefix (resp->str, "HTTP/1.1 101"));
    g_string_free (resp, TRUE);
    if (!upgraded)
        goto fail;

    return ws;

fail:
    SSL_free (ssl);
    close (fd);
    g_free (ws);
    return NULL;
}

static void
ws_free (WsConn *ws)
{
    if (!ws) return;
    if (ws->ssl) {
        SSL_shutdown (ws->ssl);
        SSL_free (ws->ssl);
    }
    if (ws->fd >= 0)
        close (ws->fd);
    g_free (ws);
}

static gboolean
ssl_write_all (SSL *ssl, const unsigned char *buf, size_t n)
{
    size_t sent = 0;
    while (sent < n) {
        int w = SSL_write (ssl, buf + sent, (int) (n - sent));
        if (w <= 0)
            return FALSE;
        sent += (size_t) w;
    }
    return TRUE;
}

static gboolean
ssl_read_exact (SSL *ssl, unsigned char *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        int r = SSL_read (ssl, buf + got, (int) (n - got));
        if (r <= 0)
            return FALSE;
        got += (size_t) r;
    }
    return TRUE;
}

static void
xor_mask (unsigned char *data, int len, const unsigned char mask[4])
{
    for (int i = 0; i < len; i++)
        data[i] ^= mask[i & 3];
}

/* Build a client-masked WebSocket frame. */
static unsigned char *
ws_build_frame (unsigned char opcode, const unsigned char *data, int n,
                gsize *out_len)
{
    unsigned char head[14];
    int hlen = 0;
    head[hlen++] = 0x80 | opcode;
    if (n < 126) {
        head[hlen++] = 0x80 | (unsigned char) n;
    } else if (n < 65536) {
        head[hlen++] = 0x80 | 126;
        head[hlen++] = (unsigned char) ((n >> 8) & 0xff);
        head[hlen++] = (unsigned char) (n & 0xff);
    } else {
        head[hlen++] = 0x80 | 127;
        for (int i = 0; i < 8; i++)
            head[hlen + i] = (unsigned char) (((guint64) n >> (8 * (7 - i))) & 0xff);
        hlen += 8;
    }
    unsigned char mask[4];
    RAND_bytes (mask, 4);
    memcpy (head + hlen, mask, 4);
    hlen += 4;

    gsize total = hlen + n;
    unsigned char *frame = g_malloc (total);
    memcpy (frame, head, hlen);
    if (n > 0) {
        memcpy (frame + hlen, data, n);
        xor_mask (frame + hlen, n, mask);
    }
    *out_len = total;
    return frame;
}

static gboolean
ws_send (WsConn *ws, const unsigned char *data, int n)
{
    gsize flen;
    unsigned char *frame = ws_build_frame (0x2 /* binary */, data, n, &flen);
    gboolean ok = ssl_write_all (ws->ssl, frame, flen);
    g_free (frame);
    return ok;
}

/* Receive one application data frame, replying to ping. Returns:
 *   1  -> out + outlen hold a payload (caller frees out),
 *   0  -> peer close,
 *  -1  -> error. */
static int
ws_recv (WsConn *ws, unsigned char **out, gsize *outlen)
{
    for (;;) {
        unsigned char hdr[2];
        if (!ssl_read_exact (ws->ssl, hdr, 2))
            return -1;
        unsigned char opcode = hdr[0] & 0x0F;
        guint64 len = hdr[1] & 0x7F;
        gboolean masked = (hdr[1] & 0x80) != 0;
        if (len == 126) {
            unsigned char e[2];
            if (!ssl_read_exact (ws->ssl, e, 2)) return -1;
            len = ((guint64) e[0] << 8) | e[1];
        } else if (len == 127) {
            unsigned char e[8];
            if (!ssl_read_exact (ws->ssl, e, 8)) return -1;
            len = 0;
            for (int i = 0; i < 8; i++) len = (len << 8) | e[i];
        }
        if (len > WS_MAX_FRAME)
            return -1;
        unsigned char mask[4];
        if (masked && !ssl_read_exact (ws->ssl, mask, 4))
            return -1;
        unsigned char *payload = NULL;
        if (len > 0) {
            payload = g_malloc (len);
            if (!ssl_read_exact (ws->ssl, payload, len)) {
                g_free (payload);
                return -1;
            }
            if (masked)
                xor_mask (payload, (int) len, mask);
        }

        if (opcode == 0x8) {            /* close */
            g_free (payload);
            ws->closed = TRUE;
            return 0;
        }
        if (opcode == 0x9) {            /* ping -> pong */
            gsize flen;
            unsigned char *pong = ws_build_frame (0xA, payload, (int) len, &flen);
            gboolean ok = ssl_write_all (ws->ssl, pong, flen);
            g_free (pong);
            g_free (payload);
            if (!ok)
                return -1;
            continue;
        }
        if (opcode == 0xA) {            /* pong */
            g_free (payload);
            continue;
        }
        *out = payload;                  /* 0x0/0x1/0x2 */
        *outlen = len;
        return 1;
    }
}

/* ============================ proxy object ============================ */

struct _TgwsProxy {
    char        *host;
    guint16      port;
    unsigned char secret[16];
    GHashTable  *dc_redirects;   /* int dc -> char* ip */

    gboolean     cfproxy;        /* Cloudflare-proxy fallback enabled */
    gboolean     verify_cf;      /* verify TLS cert for CF/worker domains */
    GPtrArray   *cf_domains;     /* char* user CF base domains (else built-ins) */
    GPtrArray   *worker_domains; /* char* CF worker domains */
    char        *fake_tls_domain;/* ee-secret masking SNI; NULL/"" = disabled */

    int          pool_size;      /* pre-warmed WS per (dc,media); 0 = disabled */
    GHashTable  *pool;           /* key (dc<<1|media) -> GQueue* of PoolEntry* */
    GHashTable  *pool_refilling; /* key -> 1 while a refill thread is in flight */
    GMutex       pool_lock;

    int          listen_fd;
    GThread     *listen_thread;
    volatile gint running;

    GMutex       stats_lock;
    gint64       conn_total;
    gint64       conn_active;
    gint64       bytes_up;
    gint64       bytes_down;
};

static void
stats_add (TgwsProxy *p, gint64 d_total, gint64 d_active,
           gint64 d_up, gint64 d_down)
{
    g_mutex_lock (&p->stats_lock);
    p->conn_total  += d_total;
    p->conn_active += d_active;
    p->bytes_up    += d_up;
    p->bytes_down  += d_down;
    g_mutex_unlock (&p->stats_lock);
}

static const char *
ws_domain_for (int dc, gboolean media, int idx, char *buf, gsize buflen)
{
    if (dc == 203) dc = 2;
    /* media: [kws{dc}-1, kws{dc}]; non-media: [kws{dc}, kws{dc}-1] */
    gboolean dash = media ? (idx == 0) : (idx == 1);
    if (dash)
        g_snprintf (buf, buflen, "kws%d-1.web.telegram.org", dc);
    else
        g_snprintf (buf, buflen, "kws%d.web.telegram.org", dc);
    return buf;
}

typedef struct {
    TgwsProxy *proxy;
    int        client_fd;
} ConnArgs;

/* ===================== client I/O (raw or fake-TLS) ===================== */

/* Wraps the client socket. In fake-TLS mode reads/writes are framed in TLS
 * application-data records (0x17 0x03 0x03 len ...); otherwise passthrough. */
typedef struct {
    int         fd;
    gboolean    fake_tls;
    GByteArray *rbuf;     /* decoded appdata awaiting consumption (fake-TLS) */
} ClientIO;

/* Read one more TLS appdata record into rbuf (skips CCS). FALSE on EOF/non-data. */
static gboolean
cio_fill_record (ClientIO *c)
{
    for (;;) {
        unsigned char hdr[5];
        if (!fd_read_exact (c->fd, hdr, 5))
            return FALSE;
        int rtype = hdr[0];
        int rec_len = (hdr[3] << 8) | hdr[4];
        if (rtype == 0x14) {                 /* ChangeCipherSpec: skip */
            if (rec_len > 0) {
                unsigned char *t = g_malloc (rec_len);
                gboolean ok = fd_read_exact (c->fd, t, rec_len);
                g_free (t);
                if (!ok) return FALSE;
            }
            continue;
        }
        if (rtype != 0x17)                   /* not application data */
            return FALSE;
        if (rec_len > 0) {
            unsigned char *body = g_malloc (rec_len);
            if (!fd_read_exact (c->fd, body, rec_len)) { g_free (body); return FALSE; }
            g_byte_array_append (c->rbuf, body, rec_len);
            g_free (body);
        }
        return TRUE;
    }
}

static gboolean
cio_read_exact (ClientIO *c, unsigned char *buf, size_t n)
{
    if (!c->fake_tls)
        return fd_read_exact (c->fd, buf, n);
    while (c->rbuf->len < n)
        if (!cio_fill_record (c))
            return FALSE;
    memcpy (buf, c->rbuf->data, n);
    g_byte_array_remove_range (c->rbuf, 0, n);
    return TRUE;
}

/* Like recv(): up to max bytes, 0 on close, -1 on error. */
static ssize_t
cio_read_some (ClientIO *c, unsigned char *buf, int max)
{
    if (!c->fake_tls)
        return recv (c->fd, buf, max, 0);
    if (c->rbuf->len == 0 && !cio_fill_record (c))
        return 0;
    int take = MIN (max, (int) c->rbuf->len);
    memcpy (buf, c->rbuf->data, take);
    g_byte_array_remove_range (c->rbuf, 0, take);
    return take;
}

static gboolean
cio_write_all (ClientIO *c, const unsigned char *buf, size_t n)
{
    if (!c->fake_tls)
        return fd_write_all (c->fd, buf, n);
    size_t off = 0;
    while (off < n) {
        int chunk = (int) MIN ((size_t) 16384, n - off);
        unsigned char hdr[5] = { 0x17, 0x03, 0x03,
                                 (unsigned char) ((chunk >> 8) & 0xff),
                                 (unsigned char) (chunk & 0xff) };
        if (!fd_write_all (c->fd, hdr, 5))
            return FALSE;
        if (!fd_write_all (c->fd, buf + off, chunk))
            return FALSE;
        off += chunk;
    }
    return TRUE;
}

/* ===================== fake-TLS (ee-secret) handshake ===================== */

/* Fixed ServerHello template (127 bytes); random@11, session_id@44, pubkey@89
 * are patched in. */
static const unsigned char SH_TEMPLATE[127] = {
    0x16,0x03,0x03,0x00,0x7a,
    0x02,0x00,0x00,0x76,
    0x03,0x03,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,   /* random */
    0x20,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,   /* sess id */
    0x13,0x01,0x00,
    0x00,0x2e,
    0x00,0x33,0x00,0x24,0x00,0x1d,0x00,0x20,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,   /* pubkey */
    0x00,0x2b,0x00,0x02,0x03,0x04
};

/* Verify a Fake-TLS ClientHello; on success fills client_random[32] +
 * session_id[32]. */
static gboolean
verify_client_hello (const unsigned char *data, int n, const unsigned char *secret,
                     unsigned char client_random[32], unsigned char session_id[32])
{
    if (n < 43 || data[0] != 0x16 || data[5] != 0x01)
        return FALSE;

    memcpy (client_random, data + 11, 32);

    unsigned char *zeroed = g_malloc (n);
    memcpy (zeroed, data, n);
    memset (zeroed + 11, 0, 32);

    unsigned char expected[32];
    unsigned int elen = 32;
    HMAC (EVP_sha256 (), secret, 16, zeroed, n, expected, &elen);
    g_free (zeroed);

    if (CRYPTO_memcmp (expected, client_random, 28) != 0)
        return FALSE;

    unsigned char ts_xor[4];
    for (int i = 0; i < 4; i++)
        ts_xor[i] = client_random[28 + i] ^ expected[28 + i];
    guint32 timestamp = ts_xor[0] | ((guint32) ts_xor[1] << 8)
                        | ((guint32) ts_xor[2] << 16) | ((guint32) ts_xor[3] << 24);
    gint64 now = (gint64) time (NULL);
    if (llabs (now - (gint64) timestamp) > 120)
        return FALSE;

    memset (session_id, 0, 32);
    if (n >= 76 && data[43] == 0x20)
        memcpy (session_id, data + 44, 32);
    return TRUE;
}

/* Build + send the Fake-TLS ServerHello (+CCS +dummy appdata). */
static gboolean
send_server_hello (int fd, const unsigned char *secret,
                   const unsigned char client_random[32],
                   const unsigned char session_id[32])
{
    static const unsigned char ccs[6] = { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
    int enc_size = 1900 + (int) (g_random_int () % 201);   /* 1900..2100 */

    int total = 127 + 6 + 5 + enc_size;
    unsigned char *resp = g_malloc (total);
    memcpy (resp, SH_TEMPLATE, 127);
    memcpy (resp + 44, session_id, 32);
    RAND_bytes (resp + 89, 32);                            /* pubkey */
    memcpy (resp + 127, ccs, 6);
    resp[133] = 0x17; resp[134] = 0x03; resp[135] = 0x03;
    resp[136] = (unsigned char) ((enc_size >> 8) & 0xff);
    resp[137] = (unsigned char) (enc_size & 0xff);
    RAND_bytes (resp + 138, enc_size);

    /* server_random = HMAC(secret, client_random + resp), patched at offset 11 */
    unsigned char *hin = g_malloc (32 + total);
    memcpy (hin, client_random, 32);
    memcpy (hin + 32, resp, total);
    unsigned char server_random[32];
    unsigned int slen = 32;
    HMAC (EVP_sha256 (), secret, 16, hin, 32 + total, server_random, &slen);
    g_free (hin);
    memcpy (resp + 11, server_random, 32);

    gboolean ok = fd_write_all (fd, resp, total);
    g_free (resp);
    return ok;
}

/* On verify failure: raw-relay the client to the masking domain:443 so a prober
 * sees a real site. */
static void
masking_passthrough (int client_fd, const char *domain,
                     const unsigned char *initial, int initial_len)
{
    int up = tcp_connect_host (domain, 443);
    if (up < 0)
        return;
    if (initial_len > 0)
        fd_write_all (up, initial, initial_len);

    unsigned char *buf = g_malloc (READ_CHUNK);
    for (;;) {
        struct pollfd pfds[2];
        pfds[0].fd = client_fd; pfds[0].events = POLLIN; pfds[0].revents = 0;
        pfds[1].fd = up;        pfds[1].events = POLLIN; pfds[1].revents = 0;
        if (poll (pfds, 2, 1000) < 0) { if (errno == EINTR) continue; break; }
        gboolean done = FALSE;
        if (pfds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t r = recv (client_fd, buf, READ_CHUNK, 0);
            if (r <= 0 || !fd_write_all (up, buf, r)) done = TRUE;
        }
        if (!done && (pfds[1].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t r = recv (up, buf, READ_CHUNK, 0);
            if (r <= 0 || !fd_write_all (client_fd, buf, r)) done = TRUE;
        }
        if (done) break;
    }
    g_free (buf);
    close (up);
}

/* The bidirectional re-encrypting bridge, single thread, poll over both fds. */
static void
bridge (TgwsProxy *p, ClientIO *cio, WsConn *ws, CryptoCtx *ctx,
        MsgSplitter *splitter)
{
    unsigned char *inbuf = g_malloc (READ_CHUNK);
    unsigned char *plain = g_malloc (READ_CHUNK);
    unsigned char *cipher = g_malloc (READ_CHUNK);
    gboolean alive = TRUE;

    while (alive && g_atomic_int_get (&p->running)) {
        struct pollfd pfds[2];
        pfds[0].fd = cio->fd;    pfds[0].events = POLLIN;  pfds[0].revents = 0;
        pfds[1].fd = ws->fd;     pfds[1].events = POLLIN;  pfds[1].revents = 0;

        int pr = poll (pfds, 2, 1000);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* client TCP -> telegram WS */
        if (pfds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t n = cio_read_some (cio, inbuf, READ_CHUNK);
            if (n <= 0) {
                GBytes *tail = splitter_flush (splitter);
                if (tail) {
                    gsize tl;
                    const guint8 *td = g_bytes_get_data (tail, &tl);
                    ws_send (ws, td, (int) tl);
                    g_bytes_unref (tail);
                }
                alive = FALSE;
            } else {
                tgws_aesctr_update (ctx->clt_dec, inbuf, plain, (int) n);
                tgws_aesctr_update (ctx->tg_enc, plain, cipher, (int) n);
                stats_add (p, 0, 0, n, 0);

                GPtrArray *parts = g_ptr_array_new_with_free_func (
                    (GDestroyNotify) g_bytes_unref);
                splitter_split (splitter, cipher, (int) n, parts);
                for (guint i = 0; i < parts->len && alive; i++) {
                    gsize pl;
                    const guint8 *pd = g_bytes_get_data (parts->pdata[i], &pl);
                    if (!ws_send (ws, pd, (int) pl))
                        alive = FALSE;
                }
                g_ptr_array_free (parts, TRUE);
            }
        }

        /* telegram WS -> client TCP (drain any buffered TLS records too) */
        if (alive && ((pfds[1].revents & (POLLIN | POLLHUP | POLLERR)) ||
                      SSL_pending (ws->ssl) > 0)) {
            do {
                unsigned char *data = NULL;
                gsize dlen = 0;
                int r = ws_recv (ws, &data, &dlen);
                if (r <= 0) {
                    alive = FALSE;
                    break;
                }
                if (dlen > 0) {
                    unsigned char *p1 = g_malloc (dlen);
                    unsigned char *p2 = g_malloc (dlen);
                    tgws_aesctr_update (ctx->tg_dec, data, p1, (int) dlen);
                    tgws_aesctr_update (ctx->clt_enc, p1, p2, (int) dlen);
                    stats_add (p, 0, 0, 0, (gint64) dlen);
                    if (!cio_write_all (cio, p2, dlen))
                        alive = FALSE;
                    g_free (p1);
                    g_free (p2);
                }
                g_free (data);
            } while (alive && SSL_pending (ws->ssl) > 0);
        }
    }

    g_free (inbuf);
    g_free (plain);
    g_free (cipher);
}

/* Plain TCP <-> TCP re-encrypting bridge (TCP fallback: no WS, no splitter). */
static void
tcp_bridge (TgwsProxy *p, ClientIO *cio, int remote_fd, CryptoCtx *ctx)
{
    unsigned char *inbuf = g_malloc (READ_CHUNK);
    unsigned char *p1 = g_malloc (READ_CHUNK);
    unsigned char *p2 = g_malloc (READ_CHUNK);
    gboolean alive = TRUE;

    while (alive && g_atomic_int_get (&p->running)) {
        struct pollfd pfds[2];
        pfds[0].fd = cio->fd;    pfds[0].events = POLLIN;  pfds[0].revents = 0;
        pfds[1].fd = remote_fd;  pfds[1].events = POLLIN;  pfds[1].revents = 0;
        int pr = poll (pfds, 2, 1000);
        if (pr < 0) { if (errno == EINTR) continue; break; }

        if (pfds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t n = cio_read_some (cio, inbuf, READ_CHUNK);
            if (n <= 0) { alive = FALSE; }
            else {
                tgws_aesctr_update (ctx->clt_dec, inbuf, p1, (int) n);
                tgws_aesctr_update (ctx->tg_enc, p1, p2, (int) n);
                stats_add (p, 0, 0, n, 0);
                if (!fd_write_all (remote_fd, p2, n)) alive = FALSE;
            }
        }
        if (alive && (pfds[1].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t n = recv (remote_fd, inbuf, READ_CHUNK, 0);
            if (n <= 0) { alive = FALSE; }
            else {
                tgws_aesctr_update (ctx->tg_dec, inbuf, p1, (int) n);
                tgws_aesctr_update (ctx->clt_enc, p1, p2, (int) n);
                stats_add (p, 0, 0, 0, n);
                if (!cio_write_all (cio, p2, n)) alive = FALSE;
            }
        }
    }
    g_free (inbuf);
    g_free (p1);
    g_free (p2);
}

/* Route a client whose DC has no direct WS redirect (or whose direct WS
 * failed): CF worker -> CF proxy -> plain TCP. Returns TRUE if it bridged. */
static gboolean
do_fallback (TgwsProxy *p, ClientIO *cio, int dc, gboolean media,
             const unsigned char *relay_init, CryptoCtx *ctx,
             MsgSplitter *splitter)
{
    const char *dst = dc_default_ip (dc);
    const char *mtag = media ? " media" : "";

    /* 1) CF worker: WSS to worker_domain with ?dst=<ip>&dc=<n> */
    if (p->worker_domains->len > 0 && dst != NULL) {
        for (guint i = 0; i < p->worker_domains->len; i++) {
            const char *wd = p->worker_domains->pdata[i];
            char path[256];
            g_snprintf (path, sizeof (path), "/apiws?dst=%s&dc=%d", dst, dc);
            WsConn *ws = ws_connect_host (wd, wd, path, p->verify_cf);
            if (ws) {
                g_message ("DC%d%s -> CF worker %s (%s)", dc, mtag, wd, dst);
                if (ws_send (ws, relay_init, HANDSHAKE_LEN))
                    bridge (p, cio, ws, ctx, splitter);
                ws_free (ws);
                return TRUE;
            }
        }
    }

    /* 2) CF proxy: WSS to kws{dc}.{base} (user domains, else built-ins) */
    if (p->cfproxy) {
        guint n = p->cf_domains->len > 0 ? p->cf_domains->len
                                         : G_N_ELEMENTS (CF_DEFAULT_DOMAINS);
        int wsdc = (dc == 203) ? 2 : dc;
        for (guint i = 0; i < n; i++) {
            const char *base = p->cf_domains->len > 0
                               ? (const char *) p->cf_domains->pdata[i]
                               : CF_DEFAULT_DOMAINS[i];
            char dom[256];
            g_snprintf (dom, sizeof (dom), "kws%d.%s", wsdc, base);
            WsConn *ws = ws_connect_host (dom, dom, "/apiws", p->verify_cf);
            if (ws) {
                g_message ("DC%d%s -> CF proxy %s", dc, mtag, dom);
                if (ws_send (ws, relay_init, HANDSHAKE_LEN))
                    bridge (p, cio, ws, ctx, splitter);
                ws_free (ws);
                return TRUE;
            }
        }
    }

    /* 3) Plain TCP to the DC IP:443 (obfuscated MTProto, no WS framing) */
    if (dst != NULL) {
        int rfd = tcp_connect_host (dst, 443);
        if (rfd >= 0) {
            g_message ("DC%d%s -> TCP fallback %s:443", dc, mtag, dst);
            if (fd_write_all (rfd, relay_init, HANDSHAKE_LEN))
                tcp_bridge (p, cio, rfd, ctx);
            close (rfd);
            return TRUE;
        }
    }
    return FALSE;
}

/* ===================== WS connection pool ===================== */
/* Pre-warmed post-upgrade WSS connections per (dc, media); 120s max age, refilled
 * in the background up to pool_size. */

#define POOL_KEY(dc, media) GINT_TO_POINTER (((dc) << 1) | ((media) ? 1 : 0))
#define POOL_MAX_AGE_US (120LL * 1000000)

typedef struct {
    WsConn *ws;
    gint64  created;   /* g_get_monotonic_time() */
} PoolEntry;

/* Cheap liveness check: dead if the socket signals hangup/error. */
static gboolean
ws_alive (WsConn *ws)
{
    struct pollfd pf = { ws->fd, POLLIN, 0 };
    if (poll (&pf, 1, 0) < 0)
        return FALSE;
    return (pf.revents & (POLLHUP | POLLERR | POLLNVAL)) == 0;
}

typedef struct { TgwsProxy *p; int dc; gboolean media; } RefillArgs;

static gpointer
pool_refill_thread (gpointer data)
{
    RefillArgs *a = data;
    TgwsProxy *p = a->p;
    int dc = a->dc;
    gboolean media = a->media;
    g_free (a);

    const char *ip = g_hash_table_lookup (p->dc_redirects, GINT_TO_POINTER (dc));
    if (ip != NULL) {
        g_mutex_lock (&p->pool_lock);
        GQueue *q = g_hash_table_lookup (p->pool, POOL_KEY (dc, media));
        int have = q ? (int) g_queue_get_length (q) : 0;
        g_mutex_unlock (&p->pool_lock);

        for (int i = have; i < p->pool_size && g_atomic_int_get (&p->running); i++) {
            WsConn *ws = NULL;
            for (int d = 0; d < 2 && !ws; d++) {
                char buf[64];
                ws = ws_connect_host (ip, ws_domain_for (dc, media, d, buf, sizeof (buf)),
                                      "/apiws", FALSE);
            }
            if (!ws)
                break;
            PoolEntry *e = g_new0 (PoolEntry, 1);
            e->ws = ws;
            e->created = g_get_monotonic_time ();
            g_mutex_lock (&p->pool_lock);
            GQueue *qq = g_hash_table_lookup (p->pool, POOL_KEY (dc, media));
            if (!qq) {
                qq = g_queue_new ();
                g_hash_table_insert (p->pool, POOL_KEY (dc, media), qq);
            }
            g_queue_push_tail (qq, e);
            g_mutex_unlock (&p->pool_lock);
        }
    }

    g_mutex_lock (&p->pool_lock);
    g_hash_table_remove (p->pool_refilling, POOL_KEY (dc, media));
    g_mutex_unlock (&p->pool_lock);
    return NULL;
}

static void
pool_schedule_refill (TgwsProxy *p, int dc, gboolean media)
{
    if (p->pool_size <= 0 || !g_atomic_int_get (&p->running))
        return;
    g_mutex_lock (&p->pool_lock);
    if (g_hash_table_contains (p->pool_refilling, POOL_KEY (dc, media))) {
        g_mutex_unlock (&p->pool_lock);
        return;
    }
    g_hash_table_insert (p->pool_refilling, POOL_KEY (dc, media), GINT_TO_POINTER (1));
    g_mutex_unlock (&p->pool_lock);

    RefillArgs *a = g_new0 (RefillArgs, 1);
    a->p = p; a->dc = dc; a->media = media;
    GThread *t = g_thread_new ("tgws-pool", pool_refill_thread, a);
    g_thread_unref (t);
}

/* Take a ready WS from the pool (NULL if none), discarding stale/dead ones, and
 * kick a background refill. */
static WsConn *
pool_get (TgwsProxy *p, int dc, gboolean media)
{
    if (p->pool_size <= 0)
        return NULL;
    gint64 now = g_get_monotonic_time ();
    WsConn *ret = NULL;
    for (;;) {
        g_mutex_lock (&p->pool_lock);
        GQueue *q = g_hash_table_lookup (p->pool, POOL_KEY (dc, media));
        PoolEntry *e = (q && !g_queue_is_empty (q)) ? g_queue_pop_head (q) : NULL;
        g_mutex_unlock (&p->pool_lock);
        if (!e)
            break;
        gint64 age = now - e->created;
        WsConn *ws = e->ws;
        g_free (e);
        if (age <= POOL_MAX_AGE_US && ws_alive (ws)) { ret = ws; break; }
        ws_free (ws);
    }
    pool_schedule_refill (p, dc, media);
    return ret;
}

static void
pool_warmup (TgwsProxy *p)
{
    if (p->pool_size <= 0)
        return;
    GHashTableIter it;
    gpointer key, val;
    g_hash_table_iter_init (&it, p->dc_redirects);
    while (g_hash_table_iter_next (&it, &key, &val)) {
        int dc = GPOINTER_TO_INT (key);
        pool_schedule_refill (p, dc, FALSE);
        pool_schedule_refill (p, dc, TRUE);
    }
}

static void
pool_drain (TgwsProxy *p)
{
    g_mutex_lock (&p->pool_lock);
    GHashTableIter it;
    gpointer key, val;
    g_hash_table_iter_init (&it, p->pool);
    while (g_hash_table_iter_next (&it, &key, &val)) {
        GQueue *q = val;
        PoolEntry *e;
        while ((e = g_queue_pop_head (q)) != NULL) {
            ws_free (e->ws);
            g_free (e);
        }
        g_queue_free (q);
    }
    g_hash_table_remove_all (p->pool);
    g_mutex_unlock (&p->pool_lock);
}

static gpointer
handle_client (gpointer data)
{
    ConnArgs *args = data;
    TgwsProxy *p = args->proxy;
    int client_fd = args->client_fd;
    g_free (args);

    stats_add (p, 1, 1, 0, 0);

    int one = 1;
    setsockopt (client_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof (one));

    CryptoCtx ctx = { 0 };
    MsgSplitter *splitter = NULL;
    WsConn *ws = NULL;
    ClientIO cio = { client_fd, FALSE, g_byte_array_new () };

    unsigned char init[HANDSHAKE_LEN];
    if (p->fake_tls_domain != NULL) {
        /* ee-secret masking: expect a TLS ClientHello (0x16 ...). */
        unsigned char first;
        if (!fd_read_exact (client_fd, &first, 1))
            goto done;
        if (first == 0x16) {
            unsigned char h4[4];
            if (!fd_read_exact (client_fd, h4, 4))
                goto done;
            int rec_len = (h4[2] << 8) | h4[3];
            int chlen = 5 + rec_len;
            unsigned char *ch = g_malloc (chlen);
            ch[0] = first;
            memcpy (ch + 1, h4, 4);
            if (rec_len > 0 && !fd_read_exact (client_fd, ch + 5, rec_len)) {
                g_free (ch);
                goto done;
            }
            unsigned char client_random[32], session_id[32];
            if (!verify_client_hello (ch, chlen, p->secret,
                                      client_random, session_id)) {
                g_message ("fake-TLS verify failed -> masking to %s",
                           p->fake_tls_domain);
                masking_passthrough (client_fd, p->fake_tls_domain, ch, chlen);
                g_free (ch);
                goto done;
            }
            g_free (ch);
            if (!send_server_hello (client_fd, p->secret, client_random, session_id))
                goto done;
            cio.fake_tls = TRUE;
            if (!cio_read_exact (&cio, init, HANDSHAKE_LEN))
                goto done;
        } else {
            /* non-TLS first byte while masking: redirect like a real web host */
            gchar *redir = g_strdup_printf (
                "HTTP/1.1 301 Moved Permanently\r\n"
                "Location: https://%s/\r\nContent-Length: 0\r\n"
                "Connection: close\r\n\r\n", p->fake_tls_domain);
            fd_write_all (client_fd, (const unsigned char *) redir, strlen (redir));
            g_free (redir);
            goto done;
        }
    } else {
        if (!fd_read_exact (client_fd, init, HANDSHAKE_LEN))
            goto done;
    }

    int dc; gboolean media; unsigned char proto[4]; unsigned char prekey_iv[48];
    if (!try_handshake (init, p->secret, &dc, &media, proto, prekey_iv)) {
        g_message ("bad handshake (wrong secret or proto)");
        goto done;
    }

    guint32 proto_int = ((guint32) proto[0] << 24) | ((guint32) proto[1] << 16)
                        | ((guint32) proto[2] << 8) | proto[3];

    gint16 dc_idx = (gint16) (media ? -dc : dc);
    unsigned char relay_init[HANDSHAKE_LEN];
    generate_relay_init (proto, dc_idx, relay_init);
    build_crypto_ctx (prekey_iv, p->secret, relay_init, &ctx);
    splitter = splitter_new (relay_init, proto_int);

    const char *ip = g_hash_table_lookup (p->dc_redirects, GINT_TO_POINTER (dc));
    if (ip != NULL) {
        ws = pool_get (p, dc, media);
        if (ws)
            g_message ("DC%d%s -> WS pool hit via %s", dc, media ? " media" : "", ip);
        for (int i = 0; i < 2 && !ws; i++) {
            char dbuf[64];
            const char *domain = ws_domain_for (dc, media, i, dbuf, sizeof (dbuf));
            ws = ws_connect_host (ip, domain, "/apiws", FALSE);
            if (ws)
                g_message ("DC%d%s -> wss://%s/apiws via %s",
                           dc, media ? " media" : "", domain, ip);
        }
        if (ws) {
            if (ws_send (ws, relay_init, HANDSHAKE_LEN))
                bridge (p, &cio, ws, &ctx, splitter);
            goto done;
        }
        g_message ("DC%d%s direct WS failed -> fallback", dc, media ? " media" : "");
    }

    if (!do_fallback (p, &cio, dc, media, relay_init, &ctx, splitter))
        g_message ("DC%d%s no route available", dc, media ? " media" : "");

done:
    if (ws) ws_free (ws);
    if (splitter) splitter_free (splitter);
    crypto_ctx_clear (&ctx);
    g_byte_array_free (cio.rbuf, TRUE);
    close (client_fd);
    stats_add (p, 0, -1, 0, 0);
    return NULL;
}

static gpointer
listen_loop (gpointer data)
{
    TgwsProxy *p = data;
    while (g_atomic_int_get (&p->running)) {
        struct sockaddr_in ca;
        socklen_t calen = sizeof (ca);
        int cfd = accept (p->listen_fd, (struct sockaddr *) &ca, &calen);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            break;   /* listen_fd shut down */
        }
        if (!g_atomic_int_get (&p->running)) {
            close (cfd);
            break;
        }
        ConnArgs *args = g_new0 (ConnArgs, 1);
        args->proxy = p;
        args->client_fd = cfd;
        GThread *t = g_thread_new ("tgws-client", handle_client, args);
        g_thread_unref (t);   /* detached */
    }
    return NULL;
}

/* ============================ public API ============================ */

TgwsProxy *
tgws_proxy_new (const char *host, guint16 port, const unsigned char *secret16)
{
    TgwsProxy *p = g_new0 (TgwsProxy, 1);
    p->host = g_strdup (host);
    p->port = port;
    memcpy (p->secret, secret16, 16);
    p->dc_redirects = g_hash_table_new_full (g_direct_hash, g_direct_equal,
                                             NULL, g_free);
    p->cfproxy = TRUE;
    p->verify_cf = TRUE;
    p->cf_domains = g_ptr_array_new_with_free_func (g_free);
    p->worker_domains = g_ptr_array_new_with_free_func (g_free);
    p->pool_size = 4;
    p->pool = g_hash_table_new (g_direct_hash, g_direct_equal);
    p->pool_refilling = g_hash_table_new (g_direct_hash, g_direct_equal);
    g_mutex_init (&p->pool_lock);
    p->listen_fd = -1;
    g_mutex_init (&p->stats_lock);
    return p;
}

void
tgws_proxy_set_pool_size (TgwsProxy *p, int size)
{
    p->pool_size = (size < 0) ? 0 : size;
}

void
tgws_proxy_add_dc (TgwsProxy *p, int dc, const char *ip)
{
    g_hash_table_insert (p->dc_redirects, GINT_TO_POINTER (dc), g_strdup (ip));
}

void
tgws_proxy_set_cfproxy (TgwsProxy *p, gboolean enabled)
{
    p->cfproxy = enabled;
}

void
tgws_proxy_set_verify_cf (TgwsProxy *p, gboolean enabled)
{
    p->verify_cf = enabled;
}

void
tgws_proxy_add_cf_domain (TgwsProxy *p, const char *domain)
{
    g_ptr_array_add (p->cf_domains, g_strdup (domain));
}

void
tgws_proxy_add_worker_domain (TgwsProxy *p, const char *domain)
{
    g_ptr_array_add (p->worker_domains, g_strdup (domain));
}

void
tgws_proxy_set_fake_tls (TgwsProxy *p, const char *domain)
{
    g_free (p->fake_tls_domain);
    p->fake_tls_domain = (domain != NULL && domain[0] != '\0')
                         ? g_strdup (domain) : NULL;
}

gboolean
tgws_proxy_start (TgwsProxy *p)
{
    int fd = socket (AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return FALSE;
    int one = 1;
    setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (one));

    struct sockaddr_in sa;
    memset (&sa, 0, sizeof (sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons (p->port);
    if (inet_pton (AF_INET, p->host, &sa.sin_addr) != 1) {
        close (fd);
        return FALSE;
    }
    if (bind (fd, (struct sockaddr *) &sa, sizeof (sa)) != 0) {
        g_warning ("bind %s:%u failed: %s", p->host, p->port, g_strerror (errno));
        close (fd);
        return FALSE;
    }
    if (listen (fd, 128) != 0) {
        close (fd);
        return FALSE;
    }
    setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof (one));

    p->listen_fd = fd;
    g_atomic_int_set (&p->running, 1);
    p->listen_thread = g_thread_new ("tgws-listen", listen_loop, p);
    pool_warmup (p);
    g_message ("Listening on %s:%u", p->host, p->port);
    return TRUE;
}

void
tgws_proxy_stop (TgwsProxy *p)
{
    if (!g_atomic_int_get (&p->running))
        return;
    g_atomic_int_set (&p->running, 0);
    if (p->listen_fd >= 0) {
        shutdown (p->listen_fd, SHUT_RDWR);
        close (p->listen_fd);
        p->listen_fd = -1;
    }
    if (p->listen_thread) {
        g_thread_join (p->listen_thread);
        p->listen_thread = NULL;
    }
}

gint64 tgws_proxy_connections_total (TgwsProxy *p)
{
    g_mutex_lock (&p->stats_lock);
    gint64 v = p->conn_total;
    g_mutex_unlock (&p->stats_lock);
    return v;
}
gint64 tgws_proxy_connections_active (TgwsProxy *p)
{
    g_mutex_lock (&p->stats_lock);
    gint64 v = p->conn_active;
    g_mutex_unlock (&p->stats_lock);
    return v;
}
gint64 tgws_proxy_bytes_up (TgwsProxy *p)
{
    g_mutex_lock (&p->stats_lock);
    gint64 v = p->bytes_up;
    g_mutex_unlock (&p->stats_lock);
    return v;
}
gint64 tgws_proxy_bytes_down (TgwsProxy *p)
{
    g_mutex_lock (&p->stats_lock);
    gint64 v = p->bytes_down;
    g_mutex_unlock (&p->stats_lock);
    return v;
}

void
tgws_proxy_free (TgwsProxy *p)
{
    if (!p) return;
    tgws_proxy_stop (p);
    pool_drain (p);
    g_hash_table_destroy (p->pool);
    g_hash_table_destroy (p->pool_refilling);
    g_mutex_clear (&p->pool_lock);
    g_hash_table_destroy (p->dc_redirects);
    g_ptr_array_free (p->cf_domains, TRUE);
    g_ptr_array_free (p->worker_domains, TRUE);
    g_free (p->fake_tls_domain);
    g_mutex_clear (&p->stats_lock);
    g_free (p->host);
    g_free (p);
}

/* ============================ self-test ============================ */

static void
print_hex (const char *label, const unsigned char *b, int n)
{
    GString *s = g_string_new (label);
    for (int i = 0; i < n; i++)
        g_string_append_printf (s, "%02x", b[i]);
    g_print ("%s\n", s->str);
    g_string_free (s, TRUE);
}

static void
ks_hex (const char *label, TgwsAesCtr *c)
{
    unsigned char z[32] = { 0 }, o[32];
    tgws_aesctr_update (c, z, o, 32);
    print_hex (label, o, 32);
}

int
tgws_engine_selftest (void)
{
    /* 1) AES-CTR + SHA256 reference vectors */
    unsigned char key[32], iv[16];
    for (int i = 0; i < 32; i++) key[i] = (unsigned char) i;
    for (int i = 0; i < 16; i++) iv[i] = (unsigned char) i;
    const char *msg = "hello tg-ws-proxy aes-ctr check!";
    int mlen = (int) strlen (msg);
    unsigned char data[32 + 64];
    memset (data, 0, 32);
    memcpy (data + 32, msg, mlen);
    unsigned char out[32 + 64];
    TgwsAesCtr *c = tgws_aesctr_new (key, iv);
    tgws_aesctr_update (c, data, out, 32 + mlen);
    tgws_aesctr_free (c);
    print_hex ("aesctr:      ", out, 32 + mlen);

    unsigned char dg[32];
    sha256 ((const unsigned char *) "abc", 3, dg);
    print_hex ("sha256(abc): ", dg, 32);

    /* 2) handshake parse + crypto-ctx (secret 00..ff, fixed handshake) */
    unsigned char secret[16];
    for (int i = 0; i < 16; i++)
        secret[i] = (unsigned char) ((i * 0x11) & 0xff);  /* 00 11 22 .. ff */

    const char *hs_hex =
        "1111111111111111000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f303132333435363738393a3b3c3d3e3f"
        "a7ca7f326bfc6583";
    unsigned char hs[HANDSHAKE_LEN];
    for (int i = 0; i < HANDSHAKE_LEN; i++) {
        unsigned int byte;
        sscanf (hs_hex + 2 * i, "%2x", &byte);
        hs[i] = (unsigned char) byte;
    }

    int dc; gboolean media; unsigned char proto[4]; unsigned char prekey_iv[48];
    if (!try_handshake (hs, secret, &dc, &media, proto, prekey_iv)) {
        g_print ("handshake: PARSE FAILED\n");
        return 1;
    }
    g_print ("handshake:   dc=%d media=%s proto=%02x%02x%02x%02x\n",
             dc, media ? "true" : "false", proto[0], proto[1], proto[2], proto[3]);

    unsigned char relay[HANDSHAKE_LEN];
    for (int i = 0; i < HANDSHAKE_LEN; i++) relay[i] = (unsigned char) i;
    CryptoCtx ctx = { 0 };
    build_crypto_ctx (prekey_iv, secret, relay, &ctx);
    ks_hex ("KS_cdec:     ", ctx.clt_dec);
    ks_hex ("KS_cenc:     ", ctx.clt_enc);
    ks_hex ("KS_tenc:     ", ctx.tg_enc);
    ks_hex ("KS_tdec:     ", ctx.tg_dec);
    crypto_ctx_clear (&ctx);
    return 0;
}
