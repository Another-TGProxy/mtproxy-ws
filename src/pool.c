/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "pool.h"
#include "proxy-internal.h"
#include "compat.h"

#define POOL_KEY(dc, media) GINT_TO_POINTER (((dc) << 1) | ((media) ? 1 : 0))
#define POOL_MAX_AGE_US     (120LL * 1000000)

typedef struct
{
    WsConn *ws;
    gint64 created; /* g_get_monotonic_time() */
} PoolEntry;

/* Cheap liveness check: dead if the socket signals hangup/error. */
static gboolean
ws_alive (WsConn *ws)
{
    struct pollfd pf = { ws->fd, POLLIN, 0 };
    if (poll (&pf, 1, 0) < 0)
        return FALSE;
    return (pf.revents & (POLLHUP | POLLERR | POLLNVAL)) == 0;
}

typedef struct
{
    TgwsProxy *p;
    int dc;
    gboolean media;
} RefillArgs;

static gpointer
pool_refill_thread (gpointer data)
{
    RefillArgs *a = data;
    TgwsProxy *p = a->p;
    int dc = a->dc;
    gboolean media = a->media;
    g_free (a);

    const char *ip = g_hash_table_lookup (p->dc_redirects, GINT_TO_POINTER (dc));
    if (ip != NULL) {
        g_mutex_lock (&p->pool_lock);
        GQueue *q = g_hash_table_lookup (p->pool, POOL_KEY (dc, media));
        int have = q ? (int) g_queue_get_length (q) : 0;
        g_mutex_unlock (&p->pool_lock);

        for (int i = have; i < p->pool_size && g_atomic_int_get (&p->running); i++) {
            WsConn *ws = NULL;
            for (int d = 0; d < 2 && !ws; d++) {
                char buf[64];
                ws = ws_connect_host (ip, ws_domain_for (dc, media, d, buf, sizeof (buf)),
                                      "/apiws", FALSE);
            }
            if (!ws)
                break;
            PoolEntry *e = g_new0 (PoolEntry, 1);
            e->ws = ws;
            e->created = g_get_monotonic_time ();
            g_mutex_lock (&p->pool_lock);
            GQueue *qq = g_hash_table_lookup (p->pool, POOL_KEY (dc, media));
            if (!qq) {
                qq = g_queue_new ();
                g_hash_table_insert (p->pool, POOL_KEY (dc, media), qq);
            }
            g_queue_push_tail (qq, e);
            g_mutex_unlock (&p->pool_lock);
        }
    }

    g_mutex_lock (&p->pool_lock);
    g_hash_table_remove (p->pool_refilling, POOL_KEY (dc, media));
    g_mutex_unlock (&p->pool_lock);
    return NULL;
}

static void
pool_schedule_refill (TgwsProxy *p, int dc, gboolean media)
{
    if (p->pool_size <= 0 || !g_atomic_int_get (&p->running))
        return;
    g_mutex_lock (&p->pool_lock);
    if (g_hash_table_contains (p->pool_refilling, POOL_KEY (dc, media))) {
        g_mutex_unlock (&p->pool_lock);
        return;
    }
    g_hash_table_insert (p->pool_refilling, POOL_KEY (dc, media), GINT_TO_POINTER (1));
    g_mutex_unlock (&p->pool_lock);

    RefillArgs *a = g_new0 (RefillArgs, 1);
    a->p = p;
    a->dc = dc;
    a->media = media;
    GThread *t = g_thread_new ("tgws-pool", pool_refill_thread, a);
    g_thread_unref (t);
}

WsConn *
pool_get (TgwsProxy *p, int dc, gboolean media)
{
    if (p->pool_size <= 0)
        return NULL;
    gint64 now = g_get_monotonic_time ();
    WsConn *ret = NULL;
    for (;;) {
        g_mutex_lock (&p->pool_lock);
        GQueue *q = g_hash_table_lookup (p->pool, POOL_KEY (dc, media));
        PoolEntry *e = (q && !g_queue_is_empty (q)) ? g_queue_pop_head (q) : NULL;
        g_mutex_unlock (&p->pool_lock);
        if (!e)
            break;
        gint64 age = now - e->created;
        WsConn *ws = e->ws;
        g_free (e);
        if (age <= POOL_MAX_AGE_US && ws_alive (ws)) {
            ret = ws;
            break;
        }
        ws_free (ws);
    }
    pool_schedule_refill (p, dc, media);
    return ret;
}

void
pool_warmup (TgwsProxy *p)
{
    if (p->pool_size <= 0)
        return;
    GHashTableIter it;
    gpointer key, val;
    g_hash_table_iter_init (&it, p->dc_redirects);
    while (g_hash_table_iter_next (&it, &key, &val)) {
        int dc = GPOINTER_TO_INT (key);
        pool_schedule_refill (p, dc, FALSE);
        pool_schedule_refill (p, dc, TRUE);
    }
}

void
pool_drain (TgwsProxy *p)
{
    g_mutex_lock (&p->pool_lock);
    GHashTableIter it;
    gpointer key, val;
    g_hash_table_iter_init (&it, p->pool);
    while (g_hash_table_iter_next (&it, &key, &val)) {
        GQueue *q = val;
        PoolEntry *e;
        while ((e = g_queue_pop_head (q)) != NULL) {
            ws_free (e->ws);
            g_free (e);
        }
        g_queue_free (q);
    }
    g_hash_table_remove_all (p->pool);
    g_mutex_unlock (&p->pool_lock);
}
