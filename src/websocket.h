/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef TGWS_WEBSOCKET_H
#define TGWS_WEBSOCKET_H

#include <glib.h>
#include <openssl/ssl.h>

/* A WSS connection: TLS socket past a completed WebSocket upgrade. */
typedef struct
{
    SSL *ssl;
    int fd;
    gboolean closed;
} WsConn;

/* TLS to connect_host:443 with SNI=sni, then the WebSocket upgrade for @path
 * with Host=sni. connect_host may be an IP or DNS name. When @verify is set the
 * peer certificate and hostname (sni) are checked; otherwise no verification
 * (used for the direct DC-IP path, where the cert won't match the IP).
 * NULL on any failure. */
WsConn *ws_connect_host (const char *connect_host, const char *sni,
                         const char *path, gboolean verify);

void ws_free (WsConn *ws);

/* Send one binary application frame. */
gboolean ws_send (WsConn *ws, const unsigned char *data, int n);

/* Receive one application data frame, replying to ping. Returns:
 *   1  -> out + outlen hold a payload (caller frees out),
 *   0  -> peer close,
 *  -1  -> error. */
int ws_recv (WsConn *ws, unsigned char **out, gsize *outlen);

#endif
