/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "splitter.h"

struct _MsgSplitter
{
    TgwsAesCtr *dec;
    guint32 proto;
    GByteArray *cipher_buf;
    GByteArray *plain_buf;
    gboolean disabled;
};

MsgSplitter *
splitter_new (const unsigned char relay_init[HANDSHAKE_LEN], guint32 proto)
{
    MsgSplitter *s = g_new0 (MsgSplitter, 1);
    s->dec = tgws_aesctr_new (relay_init + SKIP_LEN,
                              relay_init + SKIP_LEN + PREKEY_LEN);
    unsigned char tmp[64];
    tgws_aesctr_update (s->dec, TGWS_ZERO_64, tmp, 64); /* fast-forward */
    s->proto = proto;
    s->cipher_buf = g_byte_array_new ();
    s->plain_buf = g_byte_array_new ();
    return s;
}

void
splitter_free (MsgSplitter *s)
{
    if (!s)
        return;
    if (s->dec)
        tgws_aesctr_free (s->dec);
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
            if (avail < 4)
                return -1;
            payload_len = (p[offset + 1] | (p[offset + 2] << 8) | (p[offset + 3] << 16)) * 4;
            header_len = 4;
        } else {
            payload_len = (first & 0x7F) * 4;
            header_len = 1;
        }
        if (payload_len <= 0)
            return 0;
        int packet_len = header_len + payload_len;
        if (avail < packet_len)
            return -1;
        return packet_len;
    }
    if (s->proto == PROTO_INTERMEDIATE_INT ||
        s->proto == PROTO_PADDED_INTERMEDIATE_INT) {
        if (avail < 4)
            return -1;
        guint32 payload_len = ((guint32) p[offset] | ((guint32) p[offset + 1] << 8) | ((guint32) p[offset + 2] << 16) | ((guint32) p[offset + 3] << 24)) & 0x7FFFFFFFu;
        if (payload_len == 0)
            return 0;
        int packet_len = 4 + (int) payload_len;
        if (avail < packet_len)
            return -1;
        return packet_len;
    }
    return 0;
}

void
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
        if (plen <= 0) { /* unknown proto: emit the rest, stop splitting */
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

GBytes *
splitter_flush (MsgSplitter *s)
{
    if (s->cipher_buf->len == 0)
        return NULL;
    GBytes *tail = g_bytes_new (s->cipher_buf->data, s->cipher_buf->len);
    g_byte_array_set_size (s->cipher_buf, 0);
    g_byte_array_set_size (s->plain_buf, 0);
    return tail;
}
