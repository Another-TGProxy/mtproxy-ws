/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef TGWS_MTPROTO_H
#define TGWS_MTPROTO_H

#include "crypto.h"
#include <glib.h>

/* MTProto obfuscated-handshake parsing and the per-session keystream context. */

/* MTProto obfuscated-handshake layout. */
#define HANDSHAKE_LEN 64
#define SKIP_LEN      8
#define PREKEY_LEN    32
#define IV_LEN        16
#define PROTO_TAG_POS 56
#define DC_IDX_POS    60

#define PROTO_ABRIDGED_INT            0xEFEFEFEFu
#define PROTO_INTERMEDIATE_INT        0xEEEEEEEEu
#define PROTO_PADDED_INTERMEDIATE_INT 0xDDDDDDDDu

/* 64 zero bytes, used to fast-forward an AES-CTR keystream past the init. */
extern const unsigned char TGWS_ZERO_64[64];

/* The four AES-CTR streams of one bridged session. */
typedef struct
{
    TgwsAesCtr *clt_dec; /* decrypt FROM client */
    TgwsAesCtr *clt_enc; /* encrypt TO client */
    TgwsAesCtr *tg_enc;  /* encrypt TO telegram */
    TgwsAesCtr *tg_dec;  /* decrypt FROM telegram */
} CryptoCtx;

void crypto_ctx_clear (CryptoCtx *c);

/* Parse the 64-byte client init. Returns FALSE on wrong secret / bad proto. */
gboolean try_handshake (const unsigned char *handshake, const unsigned char *secret,
                        int *out_dc, gboolean *out_media, unsigned char out_proto[4],
                        unsigned char out_prekey_iv[48]);

/* Build the obfuscated 64-byte init sent to Telegram. */
void generate_relay_init (const unsigned char proto_tag[4], gint16 dc_idx,
                          unsigned char out[HANDSHAKE_LEN]);

/* Derive the four session keystreams from the client init + relay init. */
void build_crypto_ctx (const unsigned char prekey_iv[48], const unsigned char *secret,
                       const unsigned char relay_init[HANDSHAKE_LEN], CryptoCtx *ctx);

#endif
