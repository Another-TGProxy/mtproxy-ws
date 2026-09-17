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
    gboolean verbose;          /* log per-connection routing/handshake details */
    GPtrArray *cf_domains;     /* char* user CF base domains (else built-ins) */
    GPtrArray *worker_domains; /* char* CF worker domains */
    char *fake_tls_domain;     /* ee-secret masking SNI; NULL/"" = disabled */

    int pool_size;              /* pre-warmed conns per pool slot; 0 = disabled */
    GHashTable *pool;           /* key (dc<<1|media) -> GQueue* of PoolEntry* */
    GHashTable *pool_refilling; /* key -> 1 while a refill thread is in flight */
    GHashTable *worker_pool;    /* key (dc<<8|widx) -> GQueue* of PoolEntry* */
    GHashTable *worker_refilling;
    GHashTable *pool_backoff;   /* key -> PoolBackoff* for the (dc,media) pool */
    GHashTable *worker_backoff; /* key -> PoolBackoff* for the worker pool */
    GMutex pool_lock;           /* guards both pools, their refilling sets and backoff */
    GThread *rotator_thread;    /* evicts stale/dead pooled conns; see pool_rotate_start */

    int listen_fd;
    GThread *listen_thread;
    volatile gint running;

    char *upstream_host;        /* SOCKS5 to reach the data centres through; NULL = straight out */
    guint16 upstream_port;
    int max_conns;              /* cap on concurrent client connections; 0 = unlimited */
    volatile gint active_conns; /* live per-client threads (cap + join-on-stop) */
    volatile gint refills;      /* live pool-refill threads (join-on-stop) */
    GMutex conns_lock;
    GHashTable *client_fds;     /* fd -> TgwsConnInfo for every live client; shutdown() on stop to unblock reads */

    /* A client left with a stale secret retries forever, hundreds of times a
     * second, and every attempt costs a thread and a log line. Failures are
     * counted per source address; one that floods is refused right after accept
     * for a moment, before anything is allocated. */
    GMutex badhs_lock;
    GHashTable *bad_peers;      /* char* addr -> BadPeer* */
    gint64 badhs_report_us;     /* when the aggregated line was last written */
    int badhs_unreported;       /* failures since then */
    gint64 badhs_total;         /* failures since start; read by the GUI */

    GMutex stats_lock;
    gint64 conn_total;
    gint64 conn_active;
    gint64 bytes_up;
    gint64 bytes_down;
};

/* Accumulate live stats (thread-safe). */
/* Credit one connection with what it moved, beside the engine's totals. */
void conn_add_bytes (TgwsProxy *p, int fd, gint64 up, gint64 down);
/* What the handshake asked for, and how it is being reached. */
void conn_note_dc (TgwsProxy *p, int fd, int dc, gboolean media);
void conn_note_route (TgwsProxy *p, int fd, const char *route);

void stats_add (TgwsProxy *p, gint64 d_total, gint64 d_active,
                gint64 d_up, gint64 d_down);

/* WS hostname for (dc, media); writes into buf, returns buf. */
const char *ws_domain_for (int dc, gboolean media, char *buf, gsize buflen);

/* Default TCP/CF fallback target IP for @dc, or NULL if unknown. */
const char *dc_default_ip (int dc);

#endif
