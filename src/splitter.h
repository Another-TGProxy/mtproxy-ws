/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef TGWS_SPLITTER_H
#define TGWS_SPLITTER_H

#include "mtproto.h"
#include <glib.h>

/* Splits the re-encrypted (to-telegram) byte stream back into discrete MTProto
 * packets so each goes out as its own WebSocket message. */
typedef struct _MsgSplitter MsgSplitter;

MsgSplitter *splitter_new (const unsigned char relay_init[HANDSHAKE_LEN], guint32 proto);
void splitter_free (MsgSplitter *s);

/* Split @chunk into packets; each emitted packet is appended to @out as a
 * GBytes (caller unrefs). */
void splitter_split (MsgSplitter *s, const unsigned char *chunk, int len,
                     GPtrArray *out);

/* Any trailing partial buffer as a GBytes (NULL if empty); caller unrefs. */
GBytes *splitter_flush (MsgSplitter *s);

#endif
