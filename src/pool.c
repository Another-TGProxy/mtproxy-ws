/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "pool.h"
#include "proxy-internal.h"
#include "compat.h"

#define POOL_KEY(dc, media)  GINT_TO_POINTER (((dc) << 1) | ((media) ? 1 : 0))
#define WORKER_KEY(dc, widx) GINT_TO_POINTER (((dc) << 8) | ((widx) & 0xff))
#define POOL_MAX_AGE_US      (120LL * 1000000)
/* Worker connections traverse one more hop, so they go stale sooner. */
#define WORKER_MAX_AGE_US    (100LL * 1000000)
#define POOL_ROTATE_INTERVAL_US (5LL * 1000000)
#define REFILL_BACKOFF_MIN_US   (1LL * 1000000)
#define REFILL_BACKOFF_MAX_US   (3600LL * 1000000)

typedef struct
{
    WsConn *ws;
    gint64 created; /* g_get_real_time(); see pool_entry_expired */
} PoolEntry;

typedef struct
{
    int failures;
    gint64 retry_after; /* g_get_real_time() */
} PoolBackoff;

/* Age is measured against the wall clock, not the monotonic one: a suspended
 * device (Android doze, Windows sleep) freezes CLOCK_MONOTONIC, so an hour in
 * a pocket would count as seconds and long-dead connections would pass as
 * fresh. A clock stepped backwards yields a negative age, which we treat as
 * expired rather than trust. */
static gboolean
pool_entry_expired (const PoolEntry *e, gint64 now, gint64 max_age)
{
    gint64 age = now - e->created;
    return age < 0 || age > max_age;
}

/* Liveness of a pre-warmed connection. Nothing has been sent on it yet, so a
 * readable socket is never good news: zero bytes is the peer's FIN, anything
 * else is an unsolicited frame (a ping or a close) that would surface as
 * garbage in the caller's MTProto stream. POLLHUP alone misses the common
 * half-closed case, where a FIN shows up as POLLIN. */
static gboolean
ws_alive (WsConn *ws)
{
    if (ws->closed)
        return FALSE;

    struct pollfd pf = { ws->fd, POLLIN, 0 };
    int r = poll (&pf, 1, 0);
    if (r < 0)
        return FALSE;
    if (r == 0)
        return TRUE;
    if (pf.revents & (POLLHUP | POLLERR | POLLNVAL))
        return FALSE;
    if (pf.revents & POLLIN) {
        char b;
        /* Safe from blocking: poll just reported the socket readable. */
        return recv (ws->fd, &b, 1, MSG_PEEK) < 0;
    }
    return TRUE;
}

/* Refill backoff. Without it an unreachable upstream turns every pool miss into
 * a fresh connect storm against an IP that is not answering anyway. Both
 * helpers run under pool_lock. */
static gboolean
backoff_blocked (GHashTable *t, gpointer key)
{
    PoolBackoff *b = g_hash_table_lookup (t, key);
    return b != NULL && g_get_real_time () < b->retry_after;
}

static void
backoff_note (GHashTable *t, gpointer key, gboolean connected)
{
    if (connected) {
        g_hash_table_remove (t, key);
        return;
    }
    PoolBackoff *b = g_hash_table_lookup (t, key);
    if (b == NULL) {
        b = g_new0 (PoolBackoff, 1);
        g_hash_table_insert (t, key, b);
    }
    b->failures++;
    gint64 delay = REFILL_BACKOFF_MIN_US << MIN (b->failures - 1, 12);
    b->retry_after = g_get_real_time () + MIN (delay, REFILL_BACKOFF_MAX_US);
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
    gboolean attempted = FALSE;
    gboolean connected = FALSE;
    if (ip != NULL) {
        g_mutex_lock (&p->pool_lock);
        GQueue *q = g_hash_table_lookup (p->pool, POOL_KEY (dc, media));
        int have = q ? (int) g_queue_get_length (q) : 0;
        g_mutex_unlock (&p->pool_lock);

        for (int i = have; i < p->pool_size && g_atomic_int_get (&p->running); i++) {
            WsConn *ws = NULL;
            attempted = TRUE;
            /* Only this queue's own host: an entry warmed against the other
               cluster is refused the moment a client uses it. */
            char buf[64];
            ws = ws_connect_host (ip, ws_domain_for (dc, media, buf, sizeof (buf)),
                                  "/apiws", FALSE);
            if (!ws)
                break;
            connected = TRUE;
            PoolEntry *e = g_new0 (PoolEntry, 1);
            e->ws = ws;
            e->created = g_get_real_time ();
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
    if (attempted)
        backoff_note (p->pool_backoff, POOL_KEY (dc, media), connected);
    g_hash_table_remove (p->pool_refilling, POOL_KEY (dc, media));
    g_mutex_unlock (&p->pool_lock);
    g_atomic_int_add (&p->refills, -1);
    return NULL;
}

static void
pool_schedule_refill (TgwsProxy *p, int dc, gboolean media)
{
    if (p->pool_size <= 0 || !g_atomic_int_get (&p->running))
        return;
    g_mutex_lock (&p->pool_lock);
    if (g_hash_table_contains (p->pool_refilling, POOL_KEY (dc, media))
        || backoff_blocked (p->pool_backoff, POOL_KEY (dc, media))) {
        g_mutex_unlock (&p->pool_lock);
        return;
    }
    g_hash_table_insert (p->pool_refilling, POOL_KEY (dc, media), GINT_TO_POINTER (1));
    g_mutex_unlock (&p->pool_lock);

    g_atomic_int_add (&p->refills, 1);   /* joined on stop() */
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
    gint64 now = g_get_real_time ();
    WsConn *ret = NULL;
    for (;;) {
        g_mutex_lock (&p->pool_lock);
        GQueue *q = g_hash_table_lookup (p->pool, POOL_KEY (dc, media));
        PoolEntry *e = (q && !g_queue_is_empty (q)) ? g_queue_pop_head (q) : NULL;
        g_mutex_unlock (&p->pool_lock);
        if (!e)
            break;
        gboolean stale = pool_entry_expired (e, now, POOL_MAX_AGE_US);
        WsConn *ws = e->ws;
        g_free (e);
        if (!stale && ws_alive (ws)) {
            ret = ws;
            break;
        }
        ws_free (ws);
    }
    pool_schedule_refill (p, dc, media);
    return ret;
}

/* ---- CF-worker fallback pool: same machinery keyed by (dc, worker index) ----
 * Worker connections target worker_domains[widx] with the DC's default IP as the
 * ?dst, so a pooled entry is specific to a (dc, widx) pair (no media split). */

typedef struct
{
    TgwsProxy *p;
    int dc;
    int widx;
} WorkerRefillArgs;

static gpointer
pool_worker_refill_thread (gpointer data)
{
    WorkerRefillArgs *a = data;
    TgwsProxy *p = a->p;
    int dc = a->dc;
    int widx = a->widx;
    g_free (a);

    const char *dst = dc_default_ip (dc);
    gboolean attempted = FALSE;
    gboolean connected = FALSE;
    /* worker_domains is fixed before start() and not mutated while running. */
    if (dst != NULL && widx >= 0 && (guint) widx < p->worker_domains->len) {
        const char *wd = p->worker_domains->pdata[widx];
        char path[256];
        g_snprintf (path, sizeof (path), "/apiws?dst=%s&dc=%d", dst, dc);

        g_mutex_lock (&p->pool_lock);
        GQueue *q = g_hash_table_lookup (p->worker_pool, WORKER_KEY (dc, widx));
        int have = q ? (int) g_queue_get_length (q) : 0;
        g_mutex_unlock (&p->pool_lock);

        for (int i = have; i < p->pool_size && g_atomic_int_get (&p->running); i++) {
            attempted = TRUE;
            WsConn *ws = ws_connect_host (wd, wd, path, p->verify_cf);
            if (!ws)
                break;
            connected = TRUE;
            PoolEntry *e = g_new0 (PoolEntry, 1);
            e->ws = ws;
            e->created = g_get_real_time ();
            g_mutex_lock (&p->pool_lock);
            GQueue *qq = g_hash_table_lookup (p->worker_pool, WORKER_KEY (dc, widx));
            if (!qq) {
                qq = g_queue_new ();
                g_hash_table_insert (p->worker_pool, WORKER_KEY (dc, widx), qq);
            }
            g_queue_push_tail (qq, e);
            g_mutex_unlock (&p->pool_lock);
        }
    }

    g_mutex_lock (&p->pool_lock);
    if (attempted)
        backoff_note (p->worker_backoff, WORKER_KEY (dc, widx), connected);
    g_hash_table_remove (p->worker_refilling, WORKER_KEY (dc, widx));
    g_mutex_unlock (&p->pool_lock);
    g_atomic_int_add (&p->refills, -1);
    return NULL;
}

static void
pool_worker_schedule_refill (TgwsProxy *p, int dc, int widx)
{
    if (p->pool_size <= 0 || !g_atomic_int_get (&p->running))
        return;
    g_mutex_lock (&p->pool_lock);
    if (g_hash_table_contains (p->worker_refilling, WORKER_KEY (dc, widx))
        || backoff_blocked (p->worker_backoff, WORKER_KEY (dc, widx))) {
        g_mutex_unlock (&p->pool_lock);
        return;
    }
    g_hash_table_insert (p->worker_refilling, WORKER_KEY (dc, widx), GINT_TO_POINTER (1));
    g_mutex_unlock (&p->pool_lock);

    g_atomic_int_add (&p->refills, 1);   /* joined on stop() */
    WorkerRefillArgs *a = g_new0 (WorkerRefillArgs, 1);
    a->p = p;
    a->dc = dc;
    a->widx = widx;
    GThread *t = g_thread_new ("tgws-wpool", pool_worker_refill_thread, a);
    g_thread_unref (t);
}

WsConn *
pool_worker_get (TgwsProxy *p, int dc, int widx)
{
    if (p->pool_size <= 0)
        return NULL;
    gint64 now = g_get_real_time ();
    WsConn *ret = NULL;
    for (;;) {
        g_mutex_lock (&p->pool_lock);
        GQueue *q = g_hash_table_lookup (p->worker_pool, WORKER_KEY (dc, widx));
        PoolEntry *e = (q && !g_queue_is_empty (q)) ? g_queue_pop_head (q) : NULL;
        g_mutex_unlock (&p->pool_lock);
        if (!e)
            break;
        gboolean stale = pool_entry_expired (e, now, WORKER_MAX_AGE_US);
        WsConn *ws = e->ws;
        g_free (e);
        if (!stale && ws_alive (ws)) {
            ret = ws;
            break;
        }
        ws_free (ws);
    }
    pool_worker_schedule_refill (p, dc, widx);
    return ret;
}

/* ---- rotator ----
 * Checking liveness only when a connection is handed out is too late: a peer
 * that closed an idle connection leaves a corpse in the queue, and whoever asks
 * next gets a channel that dies mid-handshake. The client reads that as a
 * broken proxy. So sweep both pools on a timer instead. */

/* Evict expired/dead entries; their sockets go to @doomed to be closed outside
 * the lock, since ws_free does a TLS shutdown. Returns entries left. */
static int
rotate_queue (GQueue *q, gint64 now, gint64 max_age, GPtrArray *doomed)
{
    GList *l = q->head;
    while (l != NULL) {
        GList *next = l->next;
        PoolEntry *e = l->data;
        if (pool_entry_expired (e, now, max_age) || !ws_alive (e->ws)) {
            g_ptr_array_add (doomed, e->ws);
            g_queue_delete_link (q, l);
            g_free (e);
        }
        l = next;
    }
    return (int) g_queue_get_length (q);
}

static void
pool_rotate_once (TgwsProxy *p)
{
    gint64 now = g_get_real_time ();
    GPtrArray *doomed = g_ptr_array_new ();
    GArray *refill_ws = g_array_new (FALSE, FALSE, sizeof (gint));
    GArray *refill_wk = g_array_new (FALSE, FALSE, sizeof (gint));
    GHashTableIter it;
    gpointer key, val;

    g_mutex_lock (&p->pool_lock);
    g_hash_table_iter_init (&it, p->pool);
    while (g_hash_table_iter_next (&it, &key, &val)) {
        if (rotate_queue (val, now, POOL_MAX_AGE_US, doomed) < p->pool_size) {
            gint k = GPOINTER_TO_INT (key);
            g_array_append_val (refill_ws, k);
        }
    }
    g_hash_table_iter_init (&it, p->worker_pool);
    while (g_hash_table_iter_next (&it, &key, &val)) {
        if (rotate_queue (val, now, WORKER_MAX_AGE_US, doomed) < p->pool_size) {
            gint k = GPOINTER_TO_INT (key);
            g_array_append_val (refill_wk, k);
        }
    }
    g_mutex_unlock (&p->pool_lock);

    for (guint i = 0; i < doomed->len; i++)
        ws_free (doomed->pdata[i]);
    if (doomed->len > 0 && p->verbose)
        g_message ("pool rotated: %u stale dropped", doomed->len);
    g_ptr_array_free (doomed, TRUE);

    for (guint i = 0; i < refill_ws->len; i++) {
        gint k = g_array_index (refill_ws, gint, i);
        pool_schedule_refill (p, k >> 1, (k & 1) != 0);
    }
    for (guint i = 0; i < refill_wk->len; i++) {
        gint k = g_array_index (refill_wk, gint, i);
        pool_worker_schedule_refill (p, k >> 8, k & 0xff);
    }
    g_array_free (refill_ws, TRUE);
    g_array_free (refill_wk, TRUE);
}

static gpointer
pool_rotate_thread (gpointer data)
{
    TgwsProxy *p = data;
    while (g_atomic_int_get (&p->running)) {
        /* Sliced so stop() isn't held up for a whole interval. */
        for (int i = 0; i < 10 && g_atomic_int_get (&p->running); i++)
            g_usleep (POOL_ROTATE_INTERVAL_US / 10);
        if (!g_atomic_int_get (&p->running))
            break;
        pool_rotate_once (p);
    }
    return NULL;
}

void
pool_rotate_start (TgwsProxy *p)
{
    if (p->pool_size <= 0 || p->rotator_thread != NULL)
        return;
    p->rotator_thread = g_thread_new ("tgws-rotate", pool_rotate_thread, p);
}

void
pool_rotate_stop (TgwsProxy *p)
{
    if (p->rotator_thread == NULL)
        return;
    g_thread_join (p->rotator_thread);
    p->rotator_thread = NULL;
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

static void
drain_table (GHashTable *t)
{
    GHashTableIter it;
    gpointer key, val;
    g_hash_table_iter_init (&it, t);
    while (g_hash_table_iter_next (&it, &key, &val)) {
        GQueue *q = val;
        PoolEntry *e;
        while ((e = g_queue_pop_head (q)) != NULL) {
            ws_free (e->ws);
            g_free (e);
        }
        g_queue_free (q);
    }
    g_hash_table_remove_all (t);
}

void
pool_drain (TgwsProxy *p)
{
    g_mutex_lock (&p->pool_lock);
    drain_table (p->pool);
    drain_table (p->worker_pool);
    g_hash_table_remove_all (p->pool_backoff);
    g_hash_table_remove_all (p->worker_backoff);
    g_mutex_unlock (&p->pool_lock);
}
