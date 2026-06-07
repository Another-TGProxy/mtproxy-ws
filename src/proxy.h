/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef TGWS_PROXY_H
#define TGWS_PROXY_H

#include <glib.h>

/* Mark the engine's exported ABI; the library is built with hidden default
 * visibility so only these symbols leave the shared object. */
#ifndef TGWS_PUBLIC
# if defined(_WIN32)
#  define TGWS_PUBLIC
# else
#  define TGWS_PUBLIC __attribute__ ((visibility ("default")))
# endif
#endif

/* MTProto <-> WebSocket bridge engine (GLib + OpenSSL).
 *
 * One TgwsProxy owns a listening socket and a thread per accepted client:
 * client TCP is re-encrypted onto a WSS connection to the Telegram DC IP, and
 * back. Typical use: construct, add DC redirects, start, poll the live stats. */

typedef struct _TgwsProxy TgwsProxy;

/* secret16 = the 16 raw bytes of the MTProto secret (32 hex chars decoded). */
TGWS_PUBLIC TgwsProxy *tgws_proxy_new (const char *host, guint16 port,
                                       const unsigned char *secret16);

/* Register DC -> target IP (the WSS endpoint reached at <ip>:443).
 * Call before tgws_proxy_start(): the routing tables are read unlocked by the
 * client/pool threads, so mutating them after start would race. */
TGWS_PUBLIC void tgws_proxy_add_dc (TgwsProxy *self, int dc, const char *ip);

/* Fallback configuration (used when a DC has no direct WS redirect, or it
 * fails): CF proxy on/off, optional user CF base domains + CF worker domains. */
TGWS_PUBLIC void tgws_proxy_set_cfproxy (TgwsProxy *self, gboolean enabled);
TGWS_PUBLIC void tgws_proxy_add_cf_domain (TgwsProxy *self, const char *domain);
TGWS_PUBLIC void tgws_proxy_add_worker_domain (TgwsProxy *self, const char *domain);

/* Verify the TLS certificate of CF proxy/worker domains (default on). The
 * direct DC-IP path is never verified (its cert can't match the IP). */
TGWS_PUBLIC void tgws_proxy_set_verify_cf (TgwsProxy *self, gboolean enabled);

/* Log per-connection routing/handshake details (default off). Off keeps the log
 * quiet on a busy or probed proxy; genuine faults are logged regardless. */
TGWS_PUBLIC void tgws_proxy_set_verbose (TgwsProxy *self, gboolean enabled);

/* Enable Fake-TLS (ee-secret) masking with the given SNI domain; "" disables. */
TGWS_PUBLIC void tgws_proxy_set_fake_tls (TgwsProxy *self, const char *domain);

/* Pre-warmed WS connections per (dc, media); 0 disables pooling (default 4). */
TGWS_PUBLIC void tgws_proxy_set_pool_size (TgwsProxy *self, int size);

/* Cap on concurrent client connections (default 4096); 0 = unlimited. A backstop
 * against thread/fd exhaustion; excess connections are refused. */
TGWS_PUBLIC void tgws_proxy_set_max_conns (TgwsProxy *self, int max_conns);

/* Bind + listen + spawn the accept thread. Returns FALSE on bind/listen error. */
TGWS_PUBLIC gboolean tgws_proxy_start (TgwsProxy *self);

/* Stop accepting and tear the listener down (in-flight sessions drain). */
TGWS_PUBLIC void tgws_proxy_stop (TgwsProxy *self);

/* Live stats (thread-safe). */
TGWS_PUBLIC gint64 tgws_proxy_connections_total (TgwsProxy *self);
TGWS_PUBLIC gint64 tgws_proxy_connections_active (TgwsProxy *self);
TGWS_PUBLIC gint64 tgws_proxy_bytes_up (TgwsProxy *self);
TGWS_PUBLIC gint64 tgws_proxy_bytes_down (TgwsProxy *self);

TGWS_PUBLIC void tgws_proxy_free (TgwsProxy *self);

/* Self-check of the crypto/handshake core; prints labeled lines, returns 0. */
TGWS_PUBLIC int tgws_engine_selftest (void);

#endif
