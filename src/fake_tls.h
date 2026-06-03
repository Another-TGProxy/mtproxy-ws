/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef TGWS_FAKE_TLS_H
#define TGWS_FAKE_TLS_H

#include <glib.h>

/* Fake-TLS (ee-secret) masking: make the proxy front look like a real TLS
 * server so a passive prober sees an ordinary HTTPS site. */

/* Verify a Fake-TLS ClientHello; on success fills client_random[32] +
 * session_id[32]. */
gboolean verify_client_hello (const unsigned char *data, int n,
                              const unsigned char *secret,
                              unsigned char client_random[32],
                              unsigned char session_id[32]);

/* Build + send the Fake-TLS ServerHello (+CCS +dummy appdata). */
gboolean send_server_hello (int fd, const unsigned char *secret,
                            const unsigned char client_random[32],
                            const unsigned char session_id[32]);

/* On verify failure: raw-relay the client to the masking domain:443 so a prober
 * sees a real site. */
void masking_passthrough (int client_fd, const char *domain,
                          const unsigned char *initial, int initial_len);

#endif
