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

/* Same, for the CF-worker fallback path: a pre-warmed post-upgrade WSS to
 * worker_domains[widx] for @dc (the relay handshake is still sent per session by
 * the caller). NULL if none ready; kicks a background refill so the next call is
 * warm. Worker connections carry no media distinction. */
WsConn *pool_worker_get (TgwsProxy *p, int dc, int widx);

/* Kick off background refills for every configured DC redirect. */
void pool_warmup (TgwsProxy *p);

/* Start/stop the rotator: a thread that evicts aged-out and dead connections
 * from both pools every POOL_ROTATE_INTERVAL and refills what it emptied.
 * Without it a connection the peer closed while idle would sit in the queue
 * until someone asks for it, and that someone gets a dead channel. */
void pool_rotate_start (TgwsProxy *p);
void pool_rotate_stop (TgwsProxy *p);

/* Close and free every pooled connection. */
void pool_drain (TgwsProxy *p);

#endif
