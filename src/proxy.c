/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "proxy.h"
#include "proxy-internal.h"
#include "crypto.h"
#include "mtproto.h"
#include "splitter.h"
#include "websocket.h"
#include "fake_tls.h"
#include "client_io.h"
#include "pool.h"
#include "bridge.h"
#include "net.h"
#include "compat.h"

#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <openssl/evp.h>

/* Per-connection routing/handshake chatter — one+ line per inbound connection.
 * Off by default so a busy or probed proxy (e.g. wrong-secret scans hammer the
 * "bad handshake" path) doesn't flood the log; enable via tgws_proxy_set_verbose.
 * Genuine faults still use g_warning unconditionally. */
#define vlog(p, ...) do { if ((p)->verbose) g_message (__VA_ARGS__); } while (0)

/* Default TCP/CF fallback target IP per DC. */
const char *
dc_default_ip (int dc)
{
    switch (dc) {
    case 1:
        return "149.154.175.50";
    case 2:
        return "149.154.167.51";
    case 3:
        return "149.154.175.100";
    case 4:
        return "149.154.167.91";
    case 5:
        return "149.154.171.5";
    case 203:
        return "91.105.192.100";
    }
    return NULL;
}

/* Built-in Cloudflare-proxied base domains, used when no user domains are set. */
static const char *CF_DEFAULT_DOMAINS[] = {
    "pclead.co.uk",
    "offshor.co.uk",
    "cakeisalie.co.uk",
    "noskomnadzor.co.uk",
    "lovetrue.co.uk",
    "sorokdva.co.uk",
    "pyatdesyatdva.co.uk",
    "kartoshka.co.uk",
    "sorokodin.co.uk",
    "pyatdesyatodin.co.uk",
};

void
stats_add (TgwsProxy *p, gint64 d_total, gint64 d_active,
           gint64 d_up, gint64 d_down)
{
    g_mutex_lock (&p->stats_lock);
    p->conn_total += d_total;
    p->conn_active += d_active;
    p->bytes_up += d_up;
    p->bytes_down += d_down;
    g_mutex_unlock (&p->stats_lock);
}

const char *
ws_domain_for (int dc, gboolean media, int idx, char *buf, gsize buflen)
{
    if (dc == 203)
        dc = 2;
    /* media: [kws{dc}-1, kws{dc}]; non-media: [kws{dc}, kws{dc}-1] */
    gboolean dash = media ? (idx == 0) : (idx == 1);
    if (dash)
        g_snprintf (buf, buflen, "kws%d-1.web.telegram.org", dc);
    else
        g_snprintf (buf, buflen, "kws%d.web.telegram.org", dc);
    return buf;
}

typedef struct
{
    TgwsProxy *proxy;
    int client_fd;
    char peer[INET6_ADDRSTRLEN];
} ConnArgs;

/* Wrong-secret storm defence. A peer that fails BADHS_BURST handshakes inside
 * BADHS_WINDOW_US is refused for BADHS_BLOCK_US: the attempts then cost one
 * accept() and one close() instead of a thread, a read and a log line. Numbers
 * are far above what a working client does (it handshakes once per connection
 * and keeps it), and the block is short enough that a client which has just
 * been given the right secret gets in on its next retry. */
#define BADHS_WINDOW_US  G_GINT64_CONSTANT (1000000)
#define BADHS_BURST      40
#define BADHS_BLOCK_US   G_GINT64_CONSTANT (3000000)
/* How often the aggregated "N bad handshakes" line may be written. */
#define BADHS_REPORT_US  G_GINT64_CONSTANT (10000000)

/* A peer that keeps failing has its close delayed: the client opens its next
 * attempt as soon as the last one is closed, so holding the failed connection
 * open puts a ceiling on how fast it can retry (1 s / delay). It costs one
 * sleeping thread per failing connection and nothing at all to a client that
 * handshakes correctly. Blocking the address outright is reserved for peers
 * that are not this machine: a local proxy sees every client as 127.0.0.1, so
 * blocking it would take the working client down with the broken one. */
#define BADHS_DELAY_AFTER 3
#define BADHS_DELAY_STEP_US G_GINT64_CONSTANT (100000)
#define BADHS_DELAY_MAX_US  G_GINT64_CONSTANT (1000000)

static gboolean
addr_is_loopback (const char *addr)
{
    return g_str_has_prefix (addr, "127.") || g_strcmp0 (addr, "::1") == 0;
}

typedef struct
{
    gint64 window_start_us;
    int fails;
    gint64 blocked_until_us;    /* remote peers only; see addr_is_loopback */
} BadPeer;

/* Entries older than this window carry no penalty any more, so they are dropped
 * once the table grows past BADHS_PEERS_MAX. */
#define BADHS_PEERS_MAX  1024
#define BADHS_STALE_US   G_GINT64_CONSTANT (60000000)

/* Called with badhs_lock held. */
static void
bad_peers_prune (TgwsProxy *p, gint64 now)
{
    GHashTableIter it;
    gpointer key, val;
    g_hash_table_iter_init (&it, p->bad_peers);
    while (g_hash_table_iter_next (&it, &key, &val)) {
        BadPeer *bp = val;
        if (now - bp->window_start_us > BADHS_STALE_US && now >= bp->blocked_until_us)
            g_hash_table_iter_remove (&it);
    }
}

/* TRUE when this connection should be dropped without spending a thread on it. */
static gboolean
bad_peer_blocked (TgwsProxy *p, const char *addr)
{
    if (addr[0] == '\0' || addr_is_loopback (addr))
        return FALSE;
    gboolean blocked = FALSE;
    g_mutex_lock (&p->badhs_lock);
    BadPeer *bp = g_hash_table_lookup (p->bad_peers, addr);
    if (bp != NULL)
        blocked = g_get_monotonic_time () < bp->blocked_until_us;
    g_mutex_unlock (&p->badhs_lock);
    return blocked;
}

/* Count one failed handshake from @addr and return how long to hold the doomed
   connection open before closing it. Blocks a remote peer that is flooding, and
   reports the total at most once per BADHS_REPORT_US. */
static gint64
bad_peer_note (TgwsProxy *p, const char *addr)
{
    gint64 now = g_get_monotonic_time ();
    gboolean just_blocked = FALSE;
    gint64 delay = 0;
    int unreported = 0;

    g_mutex_lock (&p->badhs_lock);
    if (addr[0] != '\0') {
        BadPeer *bp = g_hash_table_lookup (p->bad_peers, addr);
        if (bp == NULL) {
            /* One entry per source address, so a scan from many addresses would
             * grow the table without bound: drop the ones that have gone quiet,
             * and once even those don't free room, stop tracking new addresses
             * rather than grow (the flood is already being reported). */
            if (g_hash_table_size (p->bad_peers) >= BADHS_PEERS_MAX)
                bad_peers_prune (p, now);
            if (g_hash_table_size (p->bad_peers) < BADHS_PEERS_MAX) {
                bp = g_new0 (BadPeer, 1);
                bp->window_start_us = now;
                g_hash_table_insert (p->bad_peers, g_strdup (addr), bp);
            }
        }
        if (bp != NULL) {
            /* Halved rather than cleared per window: a peer that keeps flooding
             * keeps its penalty, while one that failed once is forgiven within
             * seconds. */
            if (now - bp->window_start_us > BADHS_WINDOW_US) {
                bp->window_start_us = now;
                bp->fails /= 2;
            }
            bp->fails++;
            if (bp->fails > BADHS_DELAY_AFTER)
                delay = MIN ((gint64) (bp->fails - BADHS_DELAY_AFTER) * BADHS_DELAY_STEP_US,
                             BADHS_DELAY_MAX_US);
            if (bp->fails >= BADHS_BURST && !addr_is_loopback (addr)
                && now >= bp->blocked_until_us) {
                bp->blocked_until_us = now + BADHS_BLOCK_US;
                bp->fails = 0;
                just_blocked = TRUE;
            }
        }
    }
    p->badhs_total++;
    p->badhs_unreported++;
    if (now - p->badhs_report_us > BADHS_REPORT_US) {
        p->badhs_report_us = now;
        unreported = p->badhs_unreported;
        p->badhs_unreported = 0;
    }
    g_mutex_unlock (&p->badhs_lock);

    if (unreported > 0)
        g_message ("%d bad handshakes (wrong secret or proto); "
                   "a client is probably configured with an old secret",
                   unreported);
    if (just_blocked)
        g_message ("%s is flooding wrong-secret handshakes — refusing it for %d s",
                   addr, (int) (BADHS_BLOCK_US / 1000000));
    return delay;
}

/* Read the client's MTProto handshake (HANDSHAKE_LEN bytes) into init. With
   fake-TLS masking it first verifies the TLS ClientHello, replies with a
   ServerHello and switches cio to TLS-record framing; a non-matching client is
   redirected/passed through. Returns FALSE (caller bails) on any failure. */
static gboolean
read_client_init (TgwsProxy *p, ClientIO *cio, unsigned char init[HANDSHAKE_LEN])
{
    int client_fd = cio->fd;
    if (p->fake_tls_domain == NULL)
        return fd_read_exact (client_fd, init, HANDSHAKE_LEN);

    /* ee-secret masking: expect a TLS ClientHello (0x16 ...). */
    unsigned char first;
    if (!fd_read_exact (client_fd, &first, 1))
        return FALSE;

    if (first != 0x16) {
        /* non-TLS first byte while masking: redirect like a real web host */
        gchar *redir = g_strdup_printf (
            "HTTP/1.1 301 Moved Permanently\r\n"
            "Location: https://%s/\r\nContent-Length: 0\r\n"
            "Connection: close\r\n\r\n",
            p->fake_tls_domain);
        fd_write_all (client_fd, (const unsigned char *) redir, strlen (redir));
        g_free (redir);
        return FALSE;
    }

    unsigned char h4[4];
    if (!fd_read_exact (client_fd, h4, 4))
        return FALSE;
    int rec_len = (h4[2] << 8) | h4[3];
    int chlen = 5 + rec_len;
    unsigned char *ch = g_malloc (chlen);
    ch[0] = first;
    memcpy (ch + 1, h4, 4);
    if (rec_len > 0 && !fd_read_exact (client_fd, ch + 5, rec_len)) {
        g_free (ch);
        return FALSE;
    }

    unsigned char client_random[32], session_id[32];
    if (!verify_client_hello (ch, chlen, p->secret, client_random, session_id)) {
        vlog (p, "fake-TLS verify failed -> masking to %s", p->fake_tls_domain);
        masking_passthrough (client_fd, p->fake_tls_domain, ch, chlen);
        g_free (ch);
        return FALSE;
    }
    g_free (ch);

    if (!send_server_hello (client_fd, p->secret, client_random, session_id))
        return FALSE;
    cio->fake_tls = TRUE;
    return cio_read_exact (cio, init, HANDSHAKE_LEN);
}

/* Route a client whose DC has no direct WS redirect (or whose direct WS
 * failed): CF worker -> CF proxy -> plain TCP. Returns TRUE if it bridged. */
static gboolean
do_fallback (TgwsProxy *p, ClientIO *cio, int dc, gboolean media,
             const unsigned char *relay_init, CryptoCtx *ctx,
             MsgSplitter *splitter)
{
    const char *dst = dc_default_ip (dc);
    const char *mtag = media ? " media" : "";

    /* 1) CF worker: WSS to worker_domain with ?dst=<ip>&dc=<n>. Visit the
     * domains in a shuffled order so load spreads across them and a slow/down
     * first domain doesn't add its connect timeout to every session. A pooled
     * (pre-warmed) connection is preferred over a cold handshake. */
    if (p->worker_domains->len > 0 && dst != NULL) {
        guint n = p->worker_domains->len;
        guint *order = g_newa (guint, n);
        for (guint i = 0; i < n; i++)
            order[i] = i;
        for (guint i = n; i > 1; i--) {
            guint j = (guint) g_random_int_range (0, (gint32) i);
            guint t = order[i - 1];
            order[i - 1] = order[j];
            order[j] = t;
        }
        for (guint k = 0; k < n; k++) {
            guint i = order[k];
            const char *wd = p->worker_domains->pdata[i];
            WsConn *ws = pool_worker_get (p, dc, (int) i);
            if (ws) {
                vlog (p, "DC%d%s -> CF worker pool hit %s (%s)", dc, mtag, wd, dst);
            } else {
                char path[256];
                g_snprintf (path, sizeof (path), "/apiws?dst=%s&dc=%d", dst, dc);
                ws = ws_connect_host (wd, wd, path, p->verify_cf);
                if (ws)
                    vlog (p, "DC%d%s -> CF worker %s (%s)", dc, mtag, wd, dst);
            }
            if (ws) {
                if (ws_send (ws, relay_init, HANDSHAKE_LEN))
                    {
                        char rb[64];
                        g_snprintf (rb, sizeof (rb), "cf-worker dc%d%s", dc, mtag);
                        bridge (p, cio, ws, ctx, splitter, rb);
                    }
                ws_free (ws);
                return TRUE;
            }
        }
    }

    /* 2) CF proxy: WSS to kws{dc}.{base} (user domains, else built-ins) */
    if (p->cfproxy) {
        guint n = p->cf_domains->len > 0 ? p->cf_domains->len
                                         : G_N_ELEMENTS (CF_DEFAULT_DOMAINS);
        int wsdc = (dc == 203) ? 2 : dc;
        for (guint i = 0; i < n; i++) {
            const char *base = p->cf_domains->len > 0
                                   ? (const char *) p->cf_domains->pdata[i]
                                   : CF_DEFAULT_DOMAINS[i];
            char dom[256];
            g_snprintf (dom, sizeof (dom), "kws%d.%s", wsdc, base);
            WsConn *ws = ws_connect_host (dom, dom, "/apiws", p->verify_cf);
            if (ws) {
                vlog (p, "DC%d%s -> CF proxy %s", dc, mtag, dom);
                if (ws_send (ws, relay_init, HANDSHAKE_LEN))
                    {
                        char rb[64];
                        g_snprintf (rb, sizeof (rb), "cf-proxy dc%d%s", dc, mtag);
                        bridge (p, cio, ws, ctx, splitter, rb);
                    }
                ws_free (ws);
                return TRUE;
            }
        }
    }

    /* 3) Plain TCP to the DC IP:443 (obfuscated MTProto, no WS framing) */
    if (dst != NULL) {
        int rfd = tcp_connect_host (dst, 443);
        if (rfd >= 0) {
            vlog (p, "DC%d%s -> TCP fallback %s:443", dc, mtag, dst);
            if (fd_write_all (rfd, relay_init, HANDSHAKE_LEN))
                tcp_bridge (p, cio, rfd, ctx);
            close_socket (rfd);
            return TRUE;
        }
    }
    return FALSE;
}

/* Run one client session: handshake, then route to a WS or fallback bridge.
   The early exits return before any resource is allocated, so the
   post-handshake flow is linear down to a single cleanup. */
static void
serve_client (TgwsProxy *p, ClientIO *cio, const char *peer)
{
    unsigned char init[HANDSHAKE_LEN];
    if (!read_client_init (p, cio, init))
        return;

    int dc;
    gboolean media;
    unsigned char proto[4];
    unsigned char prekey_iv[48];
    if (!try_handshake (init, p->secret, &dc, &media, proto, prekey_iv)) {
        gint64 penalty = bad_peer_note (p, peer);
        /* Sliced so stop() still tears the connection down promptly. */
        for (gint64 slept = 0; slept < penalty && g_atomic_int_get (&p->running);
             slept += 50000)
            g_usleep (50000);
        return;
    }

    guint32 proto_int = ((guint32) proto[0] << 24) | ((guint32) proto[1] << 16) | ((guint32) proto[2] << 8) | proto[3];

    gint16 dc_idx = (gint16) (media ? -dc : dc);
    char dctag[32];
    g_snprintf (dctag, sizeof (dctag), "dc%d%s", dc, media ? " media" : "");
    unsigned char relay_init[HANDSHAKE_LEN];
    generate_relay_init (proto, dc_idx, relay_init);

    CryptoCtx ctx = { 0 };
    build_crypto_ctx (prekey_iv, p->secret, relay_init, &ctx);
    MsgSplitter *splitter = splitter_new (relay_init, proto_int);
    WsConn *ws = NULL;
    gboolean routed = FALSE;

    const char *ip = g_hash_table_lookup (p->dc_redirects, GINT_TO_POINTER (dc));
    if (ip != NULL) {
        char route_buf[64];
        const char *route = route_buf;
        g_snprintf (route_buf, sizeof (route_buf), "pool %s", dctag);
        gboolean pool_alt = FALSE;
        ws = pool_get (p, dc, media, &pool_alt);
        if (ws) {
            g_snprintf (route_buf, sizeof (route_buf), "pool%s %s",
                        pool_alt ? "-alt" : "", dctag);
            vlog (p, "DC%d%s -> WS pool hit via %s%s", dc, media ? " media" : "", ip,
                  pool_alt ? " (warmed on the -1 host)" : "");
        }
        for (int i = 0; i < 2 && !ws; i++) {
            char dbuf[64];
            const char *domain = ws_domain_for (dc, media, i, dbuf, sizeof (dbuf));
            ws = ws_connect_host (ip, domain, "/apiws", FALSE);
            if (ws) {
                g_snprintf (route_buf, sizeof (route_buf), "%s %s",
                            (i == 0) ? "direct" : "direct-alt", dctag);
                vlog (p, "DC%d%s -> wss://%s/apiws via %s",
                      dc, media ? " media" : "", domain, ip);
            }
        }
        if (ws) {
            if (ws_send (ws, relay_init, HANDSHAKE_LEN))
                bridge (p, cio, ws, &ctx, splitter, route);
            routed = TRUE;
        } else {
            vlog (p, "DC%d%s direct WS failed -> fallback", dc, media ? " media" : "");
        }
    }

    if (!routed && !do_fallback (p, cio, dc, media, relay_init, &ctx, splitter))
        vlog (p, "DC%d%s no route available", dc, media ? " media" : "");

    if (ws)
        ws_free (ws);
    splitter_free (splitter);
    crypto_ctx_clear (&ctx);
}

/* Idle timeout (s) on client sockets: bounds slowloris — a peer that stalls
 * mid-handshake is reaped instead of pinning a thread+fd forever. Active bridges
 * are poll-driven, so a live-but-idle session never trips this. */
#define CLIENT_IO_TIMEOUT 60
/* Default ceiling on concurrent client connections (one thread each); a backstop
 * against thread/fd exhaustion. tgws_proxy_set_max_conns(0) lifts it. */
#define DEFAULT_MAX_CONNS 4096

/* Track live client fds so stop() can shutdown() them and unblock their reads. */
static void
conn_register (TgwsProxy *p, int fd)
{
    g_mutex_lock (&p->conns_lock);
    g_hash_table_add (p->client_fds, GINT_TO_POINTER (fd));
    g_mutex_unlock (&p->conns_lock);
}

static void
conn_unregister (TgwsProxy *p, int fd)
{
    g_mutex_lock (&p->conns_lock);
    g_hash_table_remove (p->client_fds, GINT_TO_POINTER (fd));
    g_mutex_unlock (&p->conns_lock);
}

static gpointer
handle_client (gpointer data)
{
    ConnArgs *args = data;
    TgwsProxy *p = args->proxy;
    int client_fd = args->client_fd;
    char args_peer[INET6_ADDRSTRLEN];
    g_strlcpy (args_peer, args->peer, sizeof (args_peer));
    g_free (args);

    stats_add (p, 1, 1, 0, 0);

    int one = 1;
    setsockopt (client_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof (one));
    tgws_set_io_timeout (client_fd, CLIENT_IO_TIMEOUT);

    ClientIO cio = { client_fd, FALSE, g_byte_array_new () };
    serve_client (p, &cio, args_peer);

    g_byte_array_free (cio.rbuf, TRUE);
    conn_unregister (p, client_fd);
    close_socket (client_fd);
    stats_add (p, 0, -1, 0, 0);
    g_atomic_int_add (&p->active_conns, -1);
    return NULL;
}

static int open_listener (TgwsProxy *p, gboolean quiet);

static gpointer
listen_loop (gpointer data)
{
    TgwsProxy *p = data;
    while (g_atomic_int_get (&p->running)) {
        struct sockaddr_in ca;
        socklen_t calen = sizeof (ca);
        int cfd = accept (p->listen_fd, (struct sockaddr *) &ca, &calen);
        if (cfd < 0) {
            if (errno == EINTR)
                continue;
            if (!g_atomic_int_get (&p->running))
                break; /* stop() closed the listener */
            /* The OS can tear the listening socket down on its own — Windows
             * does it as WinError 64 (ERROR_NETNAME_DELETED) after adapter or
             * link changes. Leaving the loop here would keep the engine flagged
             * as running while nothing accepts any more, so rebuild instead. */
            g_warning ("accept failed (%s); rebuilding the listener",
                       g_strerror (errno));
            close_socket (p->listen_fd);
            p->listen_fd = -1;
            int nfd = -1;
            for (int attempt = 0; attempt < 30 && g_atomic_int_get (&p->running); attempt++) {
                nfd = open_listener (p, TRUE);
                if (nfd >= 0)
                    break;
                g_usleep (500000);
            }
            if (nfd < 0)
                break; /* port is gone for good; stop accepting */
            p->listen_fd = nfd;
            g_message ("Listening on %s:%u again", p->host, p->port);
            continue;
        }
        if (!g_atomic_int_get (&p->running)) {
            close_socket (cfd);
            break;
        }
        char peer[INET6_ADDRSTRLEN];
        peer[0] = '\0';
        getnameinfo ((struct sockaddr *) &ca, calen, peer, sizeof (peer),
                     NULL, 0, NI_NUMERICHOST);
        /* Refuse a peer that is flooding wrong-secret handshakes before it costs
         * a thread; see bad_peer_note. */
        if (bad_peer_blocked (p, peer)) {
            close_socket (cfd);
            continue;
        }
        /* Refuse beyond the concurrency cap instead of spawning unbounded threads. */
        if (p->max_conns > 0 && g_atomic_int_get (&p->active_conns) >= p->max_conns) {
            vlog (p, "connection cap (%d) reached — refusing", p->max_conns);
            close_socket (cfd);
            continue;
        }
#ifdef SO_NOSIGPIPE
        /* macOS: suppress SIGPIPE on writes to this client (no MSG_NOSIGNAL). */
        {
            int one = 1;
            setsockopt (cfd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof (one));
        }
#endif
        conn_register (p, cfd);
        g_atomic_int_add (&p->active_conns, 1);
        ConnArgs *args = g_new0 (ConnArgs, 1);
        args->proxy = p;
        args->client_fd = cfd;
        g_strlcpy (args->peer, peer, sizeof (args->peer));
        GThread *t = g_thread_new ("tgws-client", handle_client, args);
        g_thread_unref (t); /* detached; counted via active_conns, joined in stop() */
    }
    return NULL;
}

/* ============================ public API ============================ */

TgwsProxy *
tgws_proxy_new (const char *host, guint16 port, const unsigned char *secret16)
{
    tgws_net_init ();
    TgwsProxy *p = g_new0 (TgwsProxy, 1);
    p->host = g_strdup (host);
    p->port = port;
    memcpy (p->secret, secret16, 16);
    p->dc_redirects = g_hash_table_new_full (g_direct_hash, g_direct_equal,
                                             NULL, g_free);
    p->cfproxy = TRUE;
    p->verify_cf = TRUE;
    p->cf_domains = g_ptr_array_new_with_free_func (g_free);
    p->worker_domains = g_ptr_array_new_with_free_func (g_free);
    p->pool_size = 4;
    p->pool = g_hash_table_new (g_direct_hash, g_direct_equal);
    p->pool_refilling = g_hash_table_new (g_direct_hash, g_direct_equal);
    p->worker_pool = g_hash_table_new (g_direct_hash, g_direct_equal);
    p->worker_refilling = g_hash_table_new (g_direct_hash, g_direct_equal);
    p->pool_backoff = g_hash_table_new_full (g_direct_hash, g_direct_equal,
                                             NULL, g_free);
    p->worker_backoff = g_hash_table_new_full (g_direct_hash, g_direct_equal,
                                               NULL, g_free);
    g_mutex_init (&p->pool_lock);
    p->listen_fd = -1;
    p->max_conns = DEFAULT_MAX_CONNS;
    g_mutex_init (&p->conns_lock);
    p->client_fds = g_hash_table_new (g_direct_hash, g_direct_equal);
    g_mutex_init (&p->badhs_lock);
    p->bad_peers = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    g_mutex_init (&p->stats_lock);
    return p;
}

void tgws_proxy_set_pool_size (TgwsProxy *p, int size)
{
    p->pool_size = (size < 0) ? 0 : size;
}

void tgws_proxy_set_max_conns (TgwsProxy *p, int max_conns)
{
    p->max_conns = (max_conns < 0) ? 0 : max_conns;
}

void tgws_proxy_add_dc (TgwsProxy *p, int dc, const char *ip)
{
    g_hash_table_insert (p->dc_redirects, GINT_TO_POINTER (dc), g_strdup (ip));
}

void tgws_proxy_set_cfproxy (TgwsProxy *p, gboolean enabled)
{
    p->cfproxy = enabled;
}

void tgws_proxy_set_verify_cf (TgwsProxy *p, gboolean enabled)
{
    p->verify_cf = enabled;
}

void tgws_proxy_set_verbose (TgwsProxy *p, gboolean enabled)
{
    p->verbose = enabled;
}

void tgws_proxy_add_cf_domain (TgwsProxy *p, const char *domain)
{
    g_ptr_array_add (p->cf_domains, g_strdup (domain));
}

void tgws_proxy_add_worker_domain (TgwsProxy *p, const char *domain)
{
    g_ptr_array_add (p->worker_domains, g_strdup (domain));
}

void tgws_proxy_set_fake_tls (TgwsProxy *p, const char *domain)
{
    g_free (p->fake_tls_domain);
    p->fake_tls_domain = (domain != NULL && domain[0] != '\0')
                             ? g_strdup (domain)
                             : NULL;
}

/* Bind and listen on host:port. Also used to rebuild the listener if the OS
 * tears it down under us (see listen_loop). Returns -1 on failure. */
static int
open_listener (TgwsProxy *p, gboolean quiet)
{
    int fd = socket (AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    int one = 1;
    setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (one));

    struct sockaddr_in sa;
    memset (&sa, 0, sizeof (sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons (p->port);
    if (inet_pton (AF_INET, p->host, &sa.sin_addr) != 1) {
        close_socket (fd);
        return -1;
    }
    if (bind (fd, (struct sockaddr *) &sa, sizeof (sa)) != 0) {
        if (!quiet)
            g_warning ("bind %s:%u failed: %s", p->host, p->port, g_strerror (errno));
        close_socket (fd);
        return -1;
    }
    if (listen (fd, 128) != 0) {
        close_socket (fd);
        return -1;
    }
    setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof (one));
    return fd;
}

gboolean
tgws_proxy_start (TgwsProxy *p)
{
    int fd = open_listener (p, FALSE);
    if (fd < 0)
        return FALSE;

    p->listen_fd = fd;
    g_atomic_int_set (&p->running, 1);
    p->listen_thread = g_thread_new ("tgws-listen", listen_loop, p);
    pool_warmup (p);
    pool_rotate_start (p);
    g_message ("Listening on %s:%u", p->host, p->port);
    return TRUE;
}

void tgws_proxy_stop (TgwsProxy *p)
{
    if (!g_atomic_int_get (&p->running))
        return;
    g_atomic_int_set (&p->running, 0);
    if (p->listen_fd >= 0) {
        shutdown (p->listen_fd, SHUT_RDWR);
        close_socket (p->listen_fd);
        p->listen_fd = -1;
    }
    if (p->listen_thread) {
        g_thread_join (p->listen_thread);
        p->listen_thread = NULL;
    }
    /* Unblock any client thread sitting in a blocking read so it exits promptly.
     * The threads are detached and drain on their own; the wait for them lives in
     * tgws_proxy_free, so stop() never blocks the caller. That matters on Android,
     * where the engine runs in-process and stop() is called on the UI thread. */
    g_mutex_lock (&p->conns_lock);
    GHashTableIter it;
    gpointer key;
    g_hash_table_iter_init (&it, p->client_fds);
    while (g_hash_table_iter_next (&it, &key, NULL))
        shutdown (GPOINTER_TO_INT (key), SHUT_RDWR);
    g_mutex_unlock (&p->conns_lock);
}

gint64 tgws_proxy_bad_handshakes (TgwsProxy *p)
{
    g_mutex_lock (&p->badhs_lock);
    gint64 v = p->badhs_total;
    g_mutex_unlock (&p->badhs_lock);
    return v;
}
gint64 tgws_proxy_connections_total (TgwsProxy *p)
{
    g_mutex_lock (&p->stats_lock);
    gint64 v = p->conn_total;
    g_mutex_unlock (&p->stats_lock);
    return v;
}
gint64 tgws_proxy_connections_active (TgwsProxy *p)
{
    g_mutex_lock (&p->stats_lock);
    gint64 v = p->conn_active;
    g_mutex_unlock (&p->stats_lock);
    return v;
}
gint64 tgws_proxy_bytes_up (TgwsProxy *p)
{
    g_mutex_lock (&p->stats_lock);
    gint64 v = p->bytes_up;
    g_mutex_unlock (&p->stats_lock);
    return v;
}
gint64 tgws_proxy_bytes_down (TgwsProxy *p)
{
    g_mutex_lock (&p->stats_lock);
    gint64 v = p->bytes_down;
    g_mutex_unlock (&p->stats_lock);
    return v;
}

void tgws_proxy_free (TgwsProxy *p)
{
    if (!p)
        return;
    tgws_proxy_stop (p);
    /* Joined here rather than in stop(): the rotator sleeps in slices, and
     * stop() must stay non-blocking for Android's UI thread. */
    pool_rotate_stop (p);
    /* Wait for the detached per-client + pool-refill threads to finish before
     * destroying the mutexes/arrays they touch (use-after-free guard). stop()
     * already shut their fds down, so they drain promptly. */
    for (int i = 0; i < 400; i++) { /* bounded ~10s safety net */
        if (g_atomic_int_get (&p->active_conns) == 0
            && g_atomic_int_get (&p->refills) == 0)
            break;
        g_usleep (25000);
    }
    pool_drain (p);
    g_hash_table_destroy (p->pool);
    g_hash_table_destroy (p->pool_refilling);
    g_hash_table_destroy (p->worker_pool);
    g_hash_table_destroy (p->worker_refilling);
    g_hash_table_destroy (p->pool_backoff);
    g_hash_table_destroy (p->worker_backoff);
    g_mutex_clear (&p->pool_lock);
    g_hash_table_destroy (p->dc_redirects);
    g_ptr_array_free (p->cf_domains, TRUE);
    g_ptr_array_free (p->worker_domains, TRUE);
    g_free (p->fake_tls_domain);
    g_hash_table_destroy (p->client_fds);
    g_mutex_clear (&p->conns_lock);
    g_hash_table_destroy (p->bad_peers);
    g_mutex_clear (&p->badhs_lock);
    g_mutex_clear (&p->stats_lock);
    g_free (p->host);
    g_free (p);
}

/* ============================ self-test ============================ */

static void
print_hex (const char *label, const unsigned char *b, int n)
{
    GString *s = g_string_new (label);
    for (int i = 0; i < n; i++)
        g_string_append_printf (s, "%02x", b[i]);
    g_print ("%s\n", s->str);
    g_string_free (s, TRUE);
}

static void
ks_hex (const char *label, TgwsAesCtr *c)
{
    unsigned char z[32] = { 0 }, o[32];
    tgws_aesctr_update (c, z, o, 32);
    print_hex (label, o, 32);
}

int tgws_engine_selftest (void)
{
    /* 1) AES-CTR + SHA256 reference vectors */
    unsigned char key[32], iv[16];
    for (int i = 0; i < 32; i++)
        key[i] = (unsigned char) i;
    for (int i = 0; i < 16; i++)
        iv[i] = (unsigned char) i;
    const char *msg = "hello tg-ws-proxy aes-ctr check!";
    int mlen = (int) strlen (msg);
    unsigned char data[32 + 64];
    memset (data, 0, 32);
    memcpy (data + 32, msg, mlen);
    unsigned char out[32 + 64];
    TgwsAesCtr *c = tgws_aesctr_new (key, iv);
    tgws_aesctr_update (c, data, out, 32 + mlen);
    tgws_aesctr_free (c);
    print_hex ("aesctr:      ", out, 32 + mlen);

    unsigned char dg[32];
    {
        unsigned int mdlen = 32;
        EVP_Digest ((const unsigned char *) "abc", 3, dg, &mdlen, EVP_sha256 (), NULL);
    }
    print_hex ("sha256(abc): ", dg, 32);

    /* 2) handshake parse + crypto-ctx (secret 00..ff, fixed handshake) */
    unsigned char secret[16];
    for (int i = 0; i < 16; i++)
        secret[i] = (unsigned char) ((i * 0x11) & 0xff); /* 00 11 22 .. ff */

    const char *hs_hex =
        "1111111111111111000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f303132333435363738393a3b3c3d3e3f"
        "a7ca7f326bfc6583";
    unsigned char hs[HANDSHAKE_LEN];
    for (int i = 0; i < HANDSHAKE_LEN; i++) {
        unsigned int byte;
        sscanf (hs_hex + 2 * i, "%2x", &byte);
        hs[i] = (unsigned char) byte;
    }

    int dc;
    gboolean media;
    unsigned char proto[4];
    unsigned char prekey_iv[48];
    if (!try_handshake (hs, secret, &dc, &media, proto, prekey_iv)) {
        g_print ("handshake: PARSE FAILED\n");
        return 1;
    }
    g_print ("handshake:   dc=%d media=%s proto=%02x%02x%02x%02x\n",
             dc, media ? "true" : "false", proto[0], proto[1], proto[2], proto[3]);

    unsigned char relay[HANDSHAKE_LEN];
    for (int i = 0; i < HANDSHAKE_LEN; i++)
        relay[i] = (unsigned char) i;
    CryptoCtx ctx = { 0 };
    build_crypto_ctx (prekey_iv, secret, relay, &ctx);
    ks_hex ("KS_cdec:     ", ctx.clt_dec);
    ks_hex ("KS_cenc:     ", ctx.clt_enc);
    ks_hex ("KS_tenc:     ", ctx.tg_enc);
    ks_hex ("KS_tdec:     ", ctx.tg_dec);
    crypto_ctx_clear (&ctx);
    return 0;
}
