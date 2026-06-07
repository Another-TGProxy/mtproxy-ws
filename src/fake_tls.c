/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fake_tls.h"
#include "net.h"
#include "compat.h"

#include <string.h>
#include <errno.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

#define READ_CHUNK 65536

/* Fixed ServerHello template (127 bytes); random@11, session_id@44, pubkey@89
 * are patched in. */
static const unsigned char SH_TEMPLATE[127] = {
    0x16, 0x03, 0x03, 0x00, 0x7a,
    0x02, 0x00, 0x00, 0x76,
    0x03, 0x03,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* random */
    0x20,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* sess id */
    0x13, 0x01, 0x00,
    0x00, 0x2e,
    0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* pubkey */
    0x00, 0x2b, 0x00, 0x02, 0x03, 0x04
};

gboolean
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
    unsigned char *hres = HMAC (EVP_sha256 (), secret, 16, zeroed, n, expected, &elen);
    g_free (zeroed);
    if (hres == NULL)
        return FALSE;

    if (CRYPTO_memcmp (expected, client_random, 28) != 0)
        return FALSE;

    unsigned char ts_xor[4];
    for (int i = 0; i < 4; i++)
        ts_xor[i] = client_random[28 + i] ^ expected[28 + i];
    guint32 timestamp = ts_xor[0] | ((guint32) ts_xor[1] << 8) | ((guint32) ts_xor[2] << 16) | ((guint32) ts_xor[3] << 24);
    gint64 now = (gint64) time (NULL);
    if (llabs (now - (gint64) timestamp) > 120)
        return FALSE;

    memset (session_id, 0, 32);
    if (n >= 76 && data[43] == 0x20)
        memcpy (session_id, data + 44, 32);
    return TRUE;
}

gboolean
send_server_hello (int fd, const unsigned char *secret,
                   const unsigned char client_random[32],
                   const unsigned char session_id[32])
{
    static const unsigned char ccs[6] = { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
    int enc_size = 1900 + (int) (g_random_int () % 201); /* 1900..2100 */

    int total = 127 + 6 + 5 + enc_size;
    unsigned char *resp = g_malloc (total);
    memcpy (resp, SH_TEMPLATE, 127);
    memcpy (resp + 44, session_id, 32);
    /* Fail closed if the RNG fails — predictable "random" would weaken the mask. */
    if (RAND_bytes (resp + 89, 32) != 1) { /* pubkey */
        g_free (resp);
        return FALSE;
    }
    memcpy (resp + 127, ccs, 6);
    resp[133] = 0x17;
    resp[134] = 0x03;
    resp[135] = 0x03;
    resp[136] = (unsigned char) ((enc_size >> 8) & 0xff);
    resp[137] = (unsigned char) (enc_size & 0xff);
    if (RAND_bytes (resp + 138, enc_size) != 1) {
        g_free (resp);
        return FALSE;
    }

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

void
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
        pfds[0].fd = client_fd;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        pfds[1].fd = up;
        pfds[1].events = POLLIN;
        pfds[1].revents = 0;
        if (poll (pfds, 2, 1000) < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        gboolean done = FALSE;
        if (pfds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t r = recv (client_fd, buf, READ_CHUNK, 0);
            if (r <= 0 || !fd_write_all (up, buf, r))
                done = TRUE;
        }
        if (!done && (pfds[1].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t r = recv (up, buf, READ_CHUNK, 0);
            if (r <= 0 || !fd_write_all (client_fd, buf, r))
                done = TRUE;
        }
        if (done)
            break;
    }
    g_free (buf);
    close_socket (up);
}
