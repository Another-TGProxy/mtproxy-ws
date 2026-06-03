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

/* client TCP <-> telegram WS (with MTProto packet splitting). */
void bridge (TgwsProxy *p, ClientIO *cio, WsConn *ws, CryptoCtx *ctx,
             MsgSplitter *splitter);

/* client TCP <-> plain TCP DC fallback (no WS framing, no splitter). */
void tcp_bridge (TgwsProxy *p, ClientIO *cio, int remote_fd, CryptoCtx *ctx);

#endif
