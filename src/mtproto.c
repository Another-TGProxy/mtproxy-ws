/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "mtproto.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

const unsigned char TGWS_ZERO_64[64] = { 0 };

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

void
crypto_ctx_clear (CryptoCtx *c)
{
    if (c->clt_dec)
        tgws_aesctr_free (c->clt_dec);
    if (c->clt_enc)
        tgws_aesctr_free (c->clt_enc);
    if (c->tg_enc)
        tgws_aesctr_free (c->tg_enc);
    if (c->tg_dec)
        tgws_aesctr_free (c->tg_dec);
    memset (c, 0, sizeof (*c));
}

gboolean
try_handshake (const unsigned char *handshake, const unsigned char *secret,
               int *out_dc, gboolean *out_media, unsigned char out_proto[4],
               unsigned char out_prekey_iv[48])
{
    const unsigned char *prekey = handshake + SKIP_LEN;          /* [8:40]  */
    const unsigned char *iv = handshake + SKIP_LEN + PREKEY_LEN; /* [40:56] */

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
    memcpy (out_prekey_iv, handshake + SKIP_LEN, 48); /* plaintext [8:56] */
    return TRUE;
}

void
generate_relay_init (const unsigned char proto_tag[4], gint16 dc_idx,
                     unsigned char out[HANDSHAKE_LEN])
{
    static const unsigned char reserved_starts[6][4] = {
        { 0x48, 0x45, 0x41, 0x44 }, /* HEAD */
        { 0x50, 0x4f, 0x53, 0x54 }, /* POST */
        { 0x47, 0x45, 0x54, 0x20 }, /* "GET " */
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
            if (memcmp (rnd, reserved_starts[i], 4) == 0) {
                bad = TRUE;
                break;
            }
        if (bad)
            continue;
        if (rnd[4] == 0 && rnd[5] == 0 && rnd[6] == 0 && rnd[7] == 0)
            continue;
        break;
    }

    const unsigned char *enc_key = rnd + SKIP_LEN;             /* [8:40]  */
    const unsigned char *enc_iv = rnd + SKIP_LEN + PREKEY_LEN; /* [40:56] */

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

void
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
    tgws_aesctr_update (ctx->clt_dec, TGWS_ZERO_64, tmp, 64);

    /* relay (telegram) side: raw key, no secret hash */
    ctx->tg_enc = tgws_aesctr_new (relay_init + SKIP_LEN,
                                   relay_init + SKIP_LEN + PREKEY_LEN);
    reverse_into (rev48, relay_init + SKIP_LEN, 48); /* reverse([8:56]) */
    ctx->tg_dec = tgws_aesctr_new (rev48, rev48 + PREKEY_LEN);

    tgws_aesctr_update (ctx->tg_enc, TGWS_ZERO_64, tmp, 64);
}
