/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "bridge.h"
#include "proxy-internal.h"
#include "net.h"

#include <errno.h>
#include <poll.h>
#include <sys/socket.h>

#define READ_CHUNK 65536

void
bridge (TgwsProxy *p, ClientIO *cio, WsConn *ws, CryptoCtx *ctx,
        MsgSplitter *splitter)
{
    unsigned char *inbuf = g_malloc (READ_CHUNK);
    unsigned char *plain = g_malloc (READ_CHUNK);
    unsigned char *cipher = g_malloc (READ_CHUNK);
    gboolean alive = TRUE;

    while (alive && g_atomic_int_get (&p->running)) {
        struct pollfd pfds[2];
        pfds[0].fd = cio->fd;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        pfds[1].fd = ws->fd;
        pfds[1].events = POLLIN;
        pfds[1].revents = 0;

        int pr = poll (pfds, 2, 1000);
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        /* client TCP -> telegram WS */
        if (pfds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t n = cio_read_some (cio, inbuf, READ_CHUNK);
            if (n <= 0) {
                GBytes *tail = splitter_flush (splitter);
                if (tail) {
                    gsize tl;
                    const guint8 *td = g_bytes_get_data (tail, &tl);
                    ws_send (ws, td, (int) tl);
                    g_bytes_unref (tail);
                }
                alive = FALSE;
            } else {
                tgws_aesctr_update (ctx->clt_dec, inbuf, plain, (int) n);
                tgws_aesctr_update (ctx->tg_enc, plain, cipher, (int) n);
                stats_add (p, 0, 0, n, 0);

                GPtrArray *parts = g_ptr_array_new_with_free_func (
                    (GDestroyNotify) g_bytes_unref);
                splitter_split (splitter, cipher, (int) n, parts);
                for (guint i = 0; i < parts->len && alive; i++) {
                    gsize pl;
                    const guint8 *pd = g_bytes_get_data (parts->pdata[i], &pl);
                    if (!ws_send (ws, pd, (int) pl))
                        alive = FALSE;
                }
                g_ptr_array_free (parts, TRUE);
            }
        }

        /* telegram WS -> client TCP (drain any buffered TLS records too) */
        if (alive && ((pfds[1].revents & (POLLIN | POLLHUP | POLLERR)) ||
                      SSL_pending (ws->ssl) > 0)) {
            do {
                unsigned char *data = NULL;
                gsize dlen = 0;
                int r = ws_recv (ws, &data, &dlen);
                if (r <= 0) {
                    alive = FALSE;
                    break;
                }
                if (dlen > 0) {
                    unsigned char *p1 = g_malloc (dlen);
                    unsigned char *p2 = g_malloc (dlen);
                    tgws_aesctr_update (ctx->tg_dec, data, p1, (int) dlen);
                    tgws_aesctr_update (ctx->clt_enc, p1, p2, (int) dlen);
                    stats_add (p, 0, 0, 0, (gint64) dlen);
                    if (!cio_write_all (cio, p2, dlen))
                        alive = FALSE;
                    g_free (p1);
                    g_free (p2);
                }
                g_free (data);
            } while (alive && SSL_pending (ws->ssl) > 0);
        }
    }

    g_free (inbuf);
    g_free (plain);
    g_free (cipher);
}

void
tcp_bridge (TgwsProxy *p, ClientIO *cio, int remote_fd, CryptoCtx *ctx)
{
    unsigned char *inbuf = g_malloc (READ_CHUNK);
    unsigned char *p1 = g_malloc (READ_CHUNK);
    unsigned char *p2 = g_malloc (READ_CHUNK);
    gboolean alive = TRUE;

    while (alive && g_atomic_int_get (&p->running)) {
        struct pollfd pfds[2];
        pfds[0].fd = cio->fd;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        pfds[1].fd = remote_fd;
        pfds[1].events = POLLIN;
        pfds[1].revents = 0;
        int pr = poll (pfds, 2, 1000);
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        if (pfds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t n = cio_read_some (cio, inbuf, READ_CHUNK);
            if (n <= 0) {
                alive = FALSE;
            } else {
                tgws_aesctr_update (ctx->clt_dec, inbuf, p1, (int) n);
                tgws_aesctr_update (ctx->tg_enc, p1, p2, (int) n);
                stats_add (p, 0, 0, n, 0);
                if (!fd_write_all (remote_fd, p2, n))
                    alive = FALSE;
            }
        }
        if (alive && (pfds[1].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t n = recv (remote_fd, inbuf, READ_CHUNK, 0);
            if (n <= 0) {
                alive = FALSE;
            } else {
                tgws_aesctr_update (ctx->tg_dec, inbuf, p1, (int) n);
                tgws_aesctr_update (ctx->clt_enc, p1, p2, (int) n);
                stats_add (p, 0, 0, 0, n);
                if (!cio_write_all (cio, p2, n))
                    alive = FALSE;
            }
        }
    }
    g_free (inbuf);
    g_free (p1);
    g_free (p2);
}
