/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef TGWS_CRYPTO_H
#define TGWS_CRYPTO_H

/* Streaming AES-256-CTR (encrypt == decrypt). Used for the MTProto obfuscation
 * keystream. Backed by OpenSSL EVP. */
typedef struct _TgwsAesCtr TgwsAesCtr;

TgwsAesCtr *tgws_aesctr_new (const unsigned char *key32, const unsigned char *iv16);
void        tgws_aesctr_update (TgwsAesCtr *c, const unsigned char *in,
                                unsigned char *out, int len);
void        tgws_aesctr_free (TgwsAesCtr *c);

#endif
