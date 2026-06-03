/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef TGWS_CLIENT_IO_H
#define TGWS_CLIENT_IO_H

#include <glib.h>
#include <sys/types.h>

/* Wraps the client socket. In fake-TLS mode reads/writes are framed in TLS
 * application-data records (0x17 0x03 0x03 len ...); otherwise passthrough. */
typedef struct
{
    int fd;
    gboolean fake_tls;
    GByteArray *rbuf; /* decoded appdata awaiting consumption (fake-TLS) */
} ClientIO;

gboolean cio_read_exact (ClientIO *c, unsigned char *buf, size_t n);

/* Like recv(): up to max bytes, 0 on close, -1 on error. */
ssize_t cio_read_some (ClientIO *c, unsigned char *buf, int max);

gboolean cio_write_all (ClientIO *c, const unsigned char *buf, size_t n);

#endif
