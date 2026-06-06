/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef TGWS_COMPAT_H
#define TGWS_COMPAT_H

/* Socket layer: BSD sockets on POSIX, Winsock on Windows. The two are close
 * enough that the engine needs only header selection and a handful of name
 * swaps (close_socket, poll, MSG_NOSIGNAL, SHUT_RDWR). */

#ifdef _WIN32

/* WSAPoll and inet_pton need the Vista+ Winsock API surface. */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <sys/types.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#ifndef SHUT_RDWR
#define SHUT_RDWR SD_BOTH
#endif

#define poll WSAPoll
#define close_socket(fd) closesocket ((SOCKET) (fd))

/* Winsock recv/send/setsockopt take char* buffers (the engine passes
 * (unsigned char*)/void*); wrap them so the call sites stay portable. The
 * macros are defined after the wrappers so the wrapper bodies call the real
 * Winsock functions. */
static inline int
tgws_recv (int fd, void *buf, size_t n, int flags)
{
    return recv ((SOCKET) fd, (char *) buf, (int) n, flags);
}
static inline int
tgws_send (int fd, const void *buf, size_t n, int flags)
{
    return send ((SOCKET) fd, (const char *) buf, (int) n, flags);
}
static inline int
tgws_setsockopt (int fd, int level, int opt, const void *val, int len)
{
    return setsockopt ((SOCKET) fd, level, opt, (const char *) val, len);
}
#define recv(fd, buf, n, flags) tgws_recv ((fd), (buf), (n), (flags))
#define send(fd, buf, n, flags) tgws_send ((fd), (buf), (n), (flags))
#define setsockopt(fd, lvl, opt, val, len) \
    tgws_setsockopt ((fd), (lvl), (opt), (val), (int) (len))

/* WSAStartup, once per process. No-op on POSIX. */
void tgws_net_init (void);

#else /* POSIX */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>

#define close_socket(fd) close (fd)

static inline void tgws_net_init (void) {}

#endif

#endif /* TGWS_COMPAT_H */
