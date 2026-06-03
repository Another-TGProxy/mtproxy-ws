/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "net.h"

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

gboolean
fd_read_exact (int fd, unsigned char *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv (fd, buf + got, n - got, 0);
        if (r <= 0) {
            if (r < 0 && errno == EINTR)
                continue;
            return FALSE;
        }
        got += (size_t) r;
    }
    return TRUE;
}

gboolean
fd_write_all (int fd, const unsigned char *buf, size_t n)
{
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = send (fd, buf + sent, n - sent, MSG_NOSIGNAL);
        if (w <= 0) {
            if (w < 0 && errno == EINTR)
                continue;
            return FALSE;
        }
        sent += (size_t) w;
    }
    return TRUE;
}

int
tcp_connect_host (const char *host, int port)
{
    struct addrinfo hints, *res = NULL;
    memset (&hints, 0, sizeof (hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char portstr[8];
    g_snprintf (portstr, sizeof (portstr), "%d", port);
    if (getaddrinfo (host, portstr, &hints, &res) != 0)
        return -1;
    int fd = -1;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket (ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0)
            continue;
        if (connect (fd, ai->ai_addr, ai->ai_addrlen) == 0)
            break;
        close (fd);
        fd = -1;
    }
    freeaddrinfo (res);
    if (fd >= 0) {
        int one = 1;
        setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof (one));
    }
    return fd;
}
