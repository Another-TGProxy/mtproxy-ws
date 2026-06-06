/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "client_io.h"
#include "net.h"
#include "compat.h"

#include <string.h>

/* Read one more TLS appdata record into rbuf (skips CCS). FALSE on EOF/non-data. */
static gboolean
cio_fill_record (ClientIO *c)
{
    for (;;) {
        unsigned char hdr[5];
        if (!fd_read_exact (c->fd, hdr, 5))
            return FALSE;
        int rtype = hdr[0];
        int rec_len = (hdr[3] << 8) | hdr[4];
        if (rtype == 0x14) { /* ChangeCipherSpec: skip */
            if (rec_len > 0) {
                unsigned char *t = g_malloc (rec_len);
                gboolean ok = fd_read_exact (c->fd, t, rec_len);
                g_free (t);
                if (!ok)
                    return FALSE;
            }
            continue;
        }
        if (rtype != 0x17) /* not application data */
            return FALSE;
        if (rec_len > 0) {
            unsigned char *body = g_malloc (rec_len);
            if (!fd_read_exact (c->fd, body, rec_len)) {
                g_free (body);
                return FALSE;
            }
            g_byte_array_append (c->rbuf, body, rec_len);
            g_free (body);
        }
        return TRUE;
    }
}

gboolean
cio_read_exact (ClientIO *c, unsigned char *buf, size_t n)
{
    if (!c->fake_tls)
        return fd_read_exact (c->fd, buf, n);
    while (c->rbuf->len < n)
        if (!cio_fill_record (c))
            return FALSE;
    memcpy (buf, c->rbuf->data, n);
    g_byte_array_remove_range (c->rbuf, 0, n);
    return TRUE;
}

ssize_t
cio_read_some (ClientIO *c, unsigned char *buf, int max)
{
    if (!c->fake_tls)
        return recv (c->fd, buf, max, 0);
    if (c->rbuf->len == 0 && !cio_fill_record (c))
        return 0;
    int take = MIN (max, (int) c->rbuf->len);
    memcpy (buf, c->rbuf->data, take);
    g_byte_array_remove_range (c->rbuf, 0, take);
    return take;
}

gboolean
cio_write_all (ClientIO *c, const unsigned char *buf, size_t n)
{
    if (!c->fake_tls)
        return fd_write_all (c->fd, buf, n);
    size_t off = 0;
    while (off < n) {
        int chunk = (int) MIN ((size_t) 16384, n - off);
        unsigned char hdr[5] = { 0x17, 0x03, 0x03,
                                 (unsigned char) ((chunk >> 8) & 0xff),
                                 (unsigned char) (chunk & 0xff) };
        if (!fd_write_all (c->fd, hdr, 5))
            return FALSE;
        if (!fd_write_all (c->fd, buf + off, chunk))
            return FALSE;
        off += chunk;
    }
    return TRUE;
}
