/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef TGWS_PROXY_INTERNAL_H
#define TGWS_PROXY_INTERNAL_H

#include "proxy.h"
#include <glib.h>

/* Shared internals of the TgwsProxy object, used by the pool/bridge modules.
 * Not installed: this header stays private to the engine build. */

struct _TgwsProxy {
    char *host;
    guint16 port;
    unsigned char secret[16];
    GHashTable *dc_redirects; /* int dc -> char* ip */

    gboolean cfproxy;          /* Cloudflare-proxy fallback enabled */
    gboolean verify_cf;        /* verify TLS cert for CF/worker domains */
    GPtrArray *cf_domains;     /* char* user CF base domains (else built-ins) */
    GPtrArray *worker_domains; /* char* CF worker domains */
    char *fake_tls_domain;     /* ee-secret masking SNI; NULL/"" = disabled */

    int pool_size;              /* pre-warmed WS per (dc,media); 0 = disabled */
    GHashTable *pool;           /* key (dc<<1|media) -> GQueue* of PoolEntry* */
    GHashTable *pool_refilling; /* key -> 1 while a refill thread is in flight */
    GMutex pool_lock;

    int listen_fd;
    GThread *listen_thread;
    volatile gint running;

    GMutex stats_lock;
    gint64 conn_total;
    gint64 conn_active;
    gint64 bytes_up;
    gint64 bytes_down;
};

/* Accumulate live stats (thread-safe). */
void stats_add (TgwsProxy *p, gint64 d_total, gint64 d_active,
                gint64 d_up, gint64 d_down);

/* WS hostname for (dc, media, idx in {0,1}); writes into buf, returns buf. */
const char *ws_domain_for (int dc, gboolean media, int idx,
                           char *buf, gsize buflen);

#endif
