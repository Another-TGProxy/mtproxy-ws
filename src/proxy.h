/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef TGWS_PROXY_H
#define TGWS_PROXY_H

#include <glib.h>

/* MTProto <-> WebSocket bridge engine (GLib + OpenSSL).
 *
 * One TgwsProxy owns a listening socket and a thread per accepted client:
 * client TCP is re-encrypted onto a WSS connection to the Telegram DC IP, and
 * back. Typical use: construct, add DC redirects, start, poll the live stats. */

typedef struct _TgwsProxy TgwsProxy;

/* secret16 = the 16 raw bytes of the MTProto secret (32 hex chars decoded). */
TgwsProxy *tgws_proxy_new (const char *host, guint16 port,
                           const unsigned char *secret16);

/* Register DC -> target IP (the WSS endpoint reached at <ip>:443). */
void tgws_proxy_add_dc (TgwsProxy *self, int dc, const char *ip);

/* Fallback configuration (used when a DC has no direct WS redirect, or it
 * fails): CF proxy on/off, optional user CF base domains + CF worker domains. */
void tgws_proxy_set_cfproxy (TgwsProxy *self, gboolean enabled);
void tgws_proxy_add_cf_domain (TgwsProxy *self, const char *domain);
void tgws_proxy_add_worker_domain (TgwsProxy *self, const char *domain);

/* Verify the TLS certificate of CF proxy/worker domains (default on). The
 * direct DC-IP path is never verified (its cert can't match the IP). */
void tgws_proxy_set_verify_cf (TgwsProxy *self, gboolean enabled);

/* Enable Fake-TLS (ee-secret) masking with the given SNI domain; "" disables. */
void tgws_proxy_set_fake_tls (TgwsProxy *self, const char *domain);

/* Pre-warmed WS connections per (dc, media); 0 disables pooling (default 4). */
void tgws_proxy_set_pool_size (TgwsProxy *self, int size);

/* Bind + listen + spawn the accept thread. Returns FALSE on bind/listen error. */
gboolean tgws_proxy_start (TgwsProxy *self);

/* Stop accepting and tear the listener down (in-flight sessions drain). */
void tgws_proxy_stop (TgwsProxy *self);

/* Live stats (thread-safe). */
gint64 tgws_proxy_connections_total  (TgwsProxy *self);
gint64 tgws_proxy_connections_active (TgwsProxy *self);
gint64 tgws_proxy_bytes_up           (TgwsProxy *self);
gint64 tgws_proxy_bytes_down         (TgwsProxy *self);

void tgws_proxy_free (TgwsProxy *self);

/* Self-check of the crypto/handshake core; prints labeled lines, returns 0. */
int tgws_engine_selftest (void);

#endif
