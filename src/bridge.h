/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef TGWS_BRIDGE_H
#define TGWS_BRIDGE_H

#include "proxy.h"
#include "websocket.h"
#include "client_io.h"
#include "splitter.h"
#include "mtproto.h"

/* The bidirectional, re-encrypting bridges that pump one client session until
 * either side closes. Single thread each, poll over both fds. */

/* client TCP <-> telegram WS (with MTProto packet splitting). @route names the
   path this session took (pool, direct vhost, CF...) and appears in the log if
   Telegram rejects the session, so a bad route can be told from a bad client. */
void bridge (TgwsProxy *p, ClientIO *cio, WsConn *ws, CryptoCtx *ctx,
             MsgSplitter *splitter, const char *route);

/* client TCP <-> plain TCP DC fallback (no WS framing, no splitter). */
void tcp_bridge (TgwsProxy *p, ClientIO *cio, int remote_fd, CryptoCtx *ctx);

#endif
