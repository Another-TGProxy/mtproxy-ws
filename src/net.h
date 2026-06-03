/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef TGWS_NET_H
#define TGWS_NET_H

#include <glib.h>
#include <sys/types.h>

/* Plain-socket I/O primitives shared across the transport modules. */

/* Read exactly n bytes from a plain fd; FALSE on EOF/error. */
gboolean fd_read_exact (int fd, unsigned char *buf, size_t n);

/* Write all n bytes to a plain fd; FALSE on error. */
gboolean fd_write_all (int fd, const unsigned char *buf, size_t n);

/* TCP connect to host:port (host may be an IP or a DNS name), TCP_NODELAY.
 * Returns the connected fd or -1 on failure. */
int tcp_connect_host (const char *host, int port);

#endif
