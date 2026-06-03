/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef TGWS_POOL_H
#define TGWS_POOL_H

#include "proxy.h"
#include "websocket.h"

/* Pre-warmed post-upgrade WSS connections per (dc, media), refilled in the
 * background. All no-ops when pool_size is 0. */

/* Take a ready WS from the pool (NULL if none), discarding stale/dead ones, and
 * kick a background refill. */
WsConn *pool_get (TgwsProxy *p, int dc, gboolean media);

/* Kick off background refills for every configured DC redirect. */
void pool_warmup (TgwsProxy *p);

/* Close and free every pooled connection. */
void pool_drain (TgwsProxy *p);

#endif
