/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "crypto.h"

#include <stdlib.h>
#include <openssl/evp.h>

struct _TgwsAesCtr {
    EVP_CIPHER_CTX *ctx;
};

TgwsAesCtr *
tgws_aesctr_new (const unsigned char *key32, const unsigned char *iv16)
{
    TgwsAesCtr *c = malloc (sizeof (TgwsAesCtr));
    if (c == NULL)
        return NULL;
    c->ctx = EVP_CIPHER_CTX_new ();
    /* CTR is symmetric: one context serves both encrypt and decrypt. Don't return
     * a half-initialised context: if init fails, free and return NULL. */
    if (c->ctx == NULL
        || EVP_EncryptInit_ex (c->ctx, EVP_aes_256_ctr (), NULL, key32, iv16) != 1) {
        if (c->ctx != NULL)
            EVP_CIPHER_CTX_free (c->ctx);
        free (c);
        return NULL;
    }
    return c;
}

void tgws_aesctr_update (TgwsAesCtr *c, const unsigned char *in,
                         unsigned char *out, int len)
{
    if (c == NULL || c->ctx == NULL)
        return;
    int outl = 0;
    EVP_EncryptUpdate (c->ctx, out, &outl, in, len);
}

void tgws_aesctr_free (TgwsAesCtr *c)
{
    if (c == NULL)
        return;
    EVP_CIPHER_CTX_free (c->ctx);
    free (c);
}
