/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "websocket.h"
#include "net.h"

#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

/* Reject WebSocket frames larger than this (a hostile/MITM server could
 * otherwise request a huge g_malloc and abort the process). */
#define WS_MAX_FRAME (1u << 20)

static SSL_CTX *g_ssl_ctx = NULL;

static gboolean ssl_write_all (SSL *ssl, const unsigned char *buf, size_t n);

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
        "/etc/ssl/certs/ca-certificates.crt",                /* Debian/Ubuntu/Arch/Flatpak */
        "/etc/pki/tls/certs/ca-bundle.crt",                  /* Fedora/RHEL */
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", /* CentOS/RHEL */
        "/etc/pki/tls/cert.pem",                             /* ALT */
        "/var/lib/ssl/cert.pem",                             /* ALT (OpenSSL dir) */
        "/etc/ssl/cert.pem",                                 /* Alpine / *BSD / macOS */
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

WsConn *
ws_connect_host (const char *connect_host, const char *sni, const char *path,
                 gboolean verify)
{
    ensure_ssl_ctx ();

    int fd = tcp_connect_host (connect_host, 443);
    if (fd < 0)
        return NULL;

    SSL *ssl = SSL_new (g_ssl_ctx);
    SSL_set_fd (ssl, fd);
    SSL_set_tlsext_host_name (ssl, sni); /* SNI */
    if (verify) {
        SSL_set_verify (ssl, SSL_VERIFY_PEER, NULL);
        SSL_set1_host (ssl, sni); /* hostname must match cert */
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
    if (!wok) {
        ws_free (ws);
        return NULL;
    }

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
    if (!upgraded) {
        ws_free (ws);
        return NULL;
    }

    return ws;
}

void
ws_free (WsConn *ws)
{
    if (!ws)
        return;
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

gboolean
ws_send (WsConn *ws, const unsigned char *data, int n)
{
    gsize flen;
    unsigned char *frame = ws_build_frame (0x2 /* binary */, data, n, &flen);
    gboolean ok = ssl_write_all (ws->ssl, frame, flen);
    g_free (frame);
    return ok;
}

int
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
            if (!ssl_read_exact (ws->ssl, e, 2))
                return -1;
            len = ((guint64) e[0] << 8) | e[1];
        } else if (len == 127) {
            unsigned char e[8];
            if (!ssl_read_exact (ws->ssl, e, 8))
                return -1;
            len = 0;
            for (int i = 0; i < 8; i++)
                len = (len << 8) | e[i];
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

        if (opcode == 0x8) { /* close */
            g_free (payload);
            ws->closed = TRUE;
            return 0;
        }
        if (opcode == 0x9) { /* ping -> pong */
            gsize flen;
            unsigned char *pong = ws_build_frame (0xA, payload, (int) len, &flen);
            gboolean ok = ssl_write_all (ws->ssl, pong, flen);
            g_free (pong);
            g_free (payload);
            if (!ok)
                return -1;
            continue;
        }
        if (opcode == 0xA) { /* pong */
            g_free (payload);
            continue;
        }
        /* data frame: ownership of *out passes to the caller, which frees it */
        *out = payload; /* 0x0/0x1/0x2 */
        *outlen = len;
        return 1;
    }
}
