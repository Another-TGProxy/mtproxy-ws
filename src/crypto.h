/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef TGWS_CRYPTO_H
#define TGWS_CRYPTO_H

#ifndef TGWS_PUBLIC
# if defined(_WIN32)
#  define TGWS_PUBLIC
# else
#  define TGWS_PUBLIC __attribute__ ((visibility ("default")))
# endif
#endif

/* Streaming AES-256-CTR (encrypt == decrypt). Used for the MTProto obfuscation
 * keystream. Backed by OpenSSL EVP. */
typedef struct _TgwsAesCtr TgwsAesCtr;

TGWS_PUBLIC TgwsAesCtr *tgws_aesctr_new (const unsigned char *key32, const unsigned char *iv16);
TGWS_PUBLIC void tgws_aesctr_update (TgwsAesCtr *c, const unsigned char *in,
                                     unsigned char *out, int len);
TGWS_PUBLIC void tgws_aesctr_free (TgwsAesCtr *c);

#endif
