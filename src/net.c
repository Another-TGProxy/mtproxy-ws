/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "net.h"
#include "compat.h"

#include <string.h>
#include <errno.h>
#ifndef _WIN32
#include <sys/time.h>   /* struct timeval for SO_RCVTIMEO */
#ifndef _WIN32
#include <fcntl.h>      /* O_NONBLOCK for the bounded connect */
#endif
#endif

/* macOS lacks MSG_NOSIGNAL; SIGPIPE is suppressed there via SO_NOSIGPIPE on the
 * socket (set in tcp_connect_host) and SIG_IGN in the executables. */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

void
tgws_set_io_timeout (int fd, int seconds)
{
#ifdef _WIN32
    DWORD ms = (DWORD) (seconds * 1000);
    setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, (const char *) &ms, sizeof (ms));
    setsockopt (fd, SOL_SOCKET, SO_SNDTIMEO, (const char *) &ms, sizeof (ms));
#else
    struct timeval tv = { seconds, 0 };
    setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof (tv));
    setsockopt (fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof (tv));
#endif
}

#ifdef _WIN32
void
tgws_net_init (void)
{
    static gsize once = 0;
    if (g_once_init_enter (&once)) {
        WSADATA wsa;
        WSAStartup (MAKEWORD (2, 2), &wsa);
        g_once_init_leave (&once, 1);
    }
}
#endif

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

/* A blocked address doesn't refuse the connection, it swallows the SYN — so a
 * blocking connect() sits on the kernel's own timeout, well over two minutes.
 * With several of those in flight (a video downloads in parallel streams) the
 * transfer stalls instead of failing over to the Cloudflare path within seconds.
 * Bound it: non-blocking connect, poll for writability, read SO_ERROR. */
#define CONNECT_TIMEOUT_MS 5000

static gboolean
connect_timed (int fd, const struct sockaddr *addr, socklen_t len, int timeout_ms)
{
#ifdef _WIN32
    u_long nb = 1;
    ioctlsocket ((SOCKET) fd, FIONBIO, &nb);
#else
    int flags = fcntl (fd, F_GETFL, 0);
    if (flags < 0 || fcntl (fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return FALSE;
#endif

    gboolean ok = FALSE;
    if (connect (fd, addr, len) == 0) {
        ok = TRUE;
    } else {
#ifdef _WIN32
        gboolean pending = (WSAGetLastError () == WSAEWOULDBLOCK);
#else
        gboolean pending = (errno == EINPROGRESS);
#endif
        if (pending) {
            struct pollfd pf = { fd, POLLOUT, 0 };
            if (poll (&pf, 1, timeout_ms) > 0 && (pf.revents & POLLOUT)) {
                int err = 0;
                socklen_t elen = sizeof (err);
                /* Writable only means the attempt finished; SO_ERROR says how. */
                if (getsockopt (fd, SOL_SOCKET, SO_ERROR, (char *) &err, &elen) == 0
                    && err == 0)
                    ok = TRUE;
            }
        }
    }

#ifdef _WIN32
    nb = 0;
    ioctlsocket ((SOCKET) fd, FIONBIO, &nb);
#else
    fcntl (fd, F_SETFL, flags);
#endif
    return ok;
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
        if (connect_timed (fd, ai->ai_addr, ai->ai_addrlen, CONNECT_TIMEOUT_MS))
            break;
        close_socket (fd);
        fd = -1;
    }
    freeaddrinfo (res);
    if (fd >= 0) {
        int one = 1;
        setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof (one));
#ifdef SO_NOSIGPIPE
        setsockopt (fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof (one));
#endif
    }
    return fd;
}
