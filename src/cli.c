/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Standalone headless CLI for the proxy engine (no GTK/Vala).
 * Self-contained: `mtproxy-ws --secret <hex> --port 1443 ...` runs the proxy on
 * a GLib main loop. The GUI is a separate optional front-end. */
#include "proxy.h"

#include <glib.h>
#include <glib-unix.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

static GMainLoop *loop;

static gboolean
on_signal (gpointer data)
{
    (void) data;
    g_main_loop_quit (loop);
    return G_SOURCE_REMOVE;
}

static gboolean
hex_to_16 (const char *hex, unsigned char out[16])
{
    if (strlen (hex) != 32)
        return FALSE;
    for (int i = 0; i < 16; i++) {
        unsigned int b;
        if (sscanf (hex + 2 * i, "%2x", &b) != 1)
            return FALSE;
        out[i] = (unsigned char) b;
    }
    return TRUE;
}

static char *
random_secret_hex (void)
{
    unsigned char r[16];
    FILE *f = fopen ("/dev/urandom", "rb");
    if (f) { size_t n = fread (r, 1, 16, f); (void) n; fclose (f); }
    else for (int i = 0; i < 16; i++) r[i] = (unsigned char) g_random_int ();
    GString *s = g_string_new (NULL);
    for (int i = 0; i < 16; i++) g_string_append_printf (s, "%02x", r[i]);
    return g_string_free (s, FALSE);
}

int
main (int argc, char **argv)
{
    gchar *host = NULL, *secret = NULL, *fake_tls = NULL;
    gint port = 1443, pool_size = 4;
    gboolean no_cfproxy = FALSE, no_verify_cf = FALSE;
    gchar **dc_ips = NULL, **cf_domains = NULL, **worker_domains = NULL;

    GOptionEntry entries[] = {
        { "host", 'H', 0, G_OPTION_ARG_STRING, &host, "Listen host (default 127.0.0.1)", "HOST" },
        { "port", 'p', 0, G_OPTION_ARG_INT, &port, "Listen port (default 1443)", "PORT" },
        { "secret", 's', 0, G_OPTION_ARG_STRING, &secret, "MTProto secret, 32 hex chars (random if omitted)", "HEX" },
        { "dc-ip", 0, 0, G_OPTION_ARG_STRING_ARRAY, &dc_ips, "DC:IP WS redirect, repeatable (default 2,4 -> 149.154.167.220)", "DC:IP" },
        { "pool-size", 0, 0, G_OPTION_ARG_INT, &pool_size, "Pre-warmed WS per DC (default 4, 0 disables)", "N" },
        { "no-cfproxy", 0, 0, G_OPTION_ARG_NONE, &no_cfproxy, "Disable Cloudflare-proxy fallback", NULL },
        { "no-verify-cf", 0, 0, G_OPTION_ARG_NONE, &no_verify_cf, "Don't verify the TLS cert of CF proxy/worker domains", NULL },
        { "cf-domain", 0, 0, G_OPTION_ARG_STRING_ARRAY, &cf_domains, "CF base domain, repeatable", "DOMAIN" },
        { "worker-domain", 0, 0, G_OPTION_ARG_STRING_ARRAY, &worker_domains, "CF worker domain, repeatable", "DOMAIN" },
        { "fake-tls-domain", 0, 0, G_OPTION_ARG_STRING, &fake_tls, "Enable Fake-TLS (ee-secret) with this SNI", "DOMAIN" },
        { NULL }
    };

    GOptionContext *ctx = g_option_context_new ("- Telegram MTProto <-> WebSocket bridge proxy");
    g_option_context_add_main_entries (ctx, entries, NULL);
    GError *err = NULL;
    if (!g_option_context_parse (ctx, &argc, &argv, &err)) {
        g_printerr ("%s\n", err->message);
        return 1;
    }
    g_option_context_free (ctx);

    if (!host) host = g_strdup ("127.0.0.1");
    if (!secret) {
        secret = random_secret_hex ();
        g_message ("Generated secret: %s", secret);
    }
    unsigned char sec[16];
    if (!hex_to_16 (secret, sec)) {
        g_printerr ("secret must be exactly 32 hex characters\n");
        return 1;
    }

    TgwsProxy *p = tgws_proxy_new (host, (guint16) port, sec);
    if (dc_ips) {
        for (int i = 0; dc_ips[i]; i++) {
            char *colon = strchr (dc_ips[i], ':');
            if (colon) { *colon = '\0'; tgws_proxy_add_dc (p, atoi (dc_ips[i]), colon + 1); }
        }
    } else {
        tgws_proxy_add_dc (p, 2, "149.154.167.220");
        tgws_proxy_add_dc (p, 4, "149.154.167.220");
    }
    tgws_proxy_set_cfproxy (p, !no_cfproxy);
    tgws_proxy_set_verify_cf (p, !no_verify_cf);
    if (cf_domains) for (int i = 0; cf_domains[i]; i++) tgws_proxy_add_cf_domain (p, cf_domains[i]);
    if (worker_domains) for (int i = 0; worker_domains[i]; i++) tgws_proxy_add_worker_domain (p, worker_domains[i]);
    if (fake_tls) tgws_proxy_set_fake_tls (p, fake_tls);
    tgws_proxy_set_pool_size (p, pool_size);

    if (!tgws_proxy_start (p)) {
        g_printerr ("failed to start proxy on %s:%d\n", host, port);
        tgws_proxy_free (p);
        return 1;
    }
    g_print ("tg://proxy?server=%s&port=%d&secret=dd%s\n", host, port, secret);

    loop = g_main_loop_new (NULL, FALSE);
    g_unix_signal_add (SIGINT, on_signal, NULL);
    g_unix_signal_add (SIGTERM, on_signal, NULL);
    g_main_loop_run (loop);

    tgws_proxy_stop (p);
    tgws_proxy_free (p);
    g_main_loop_unref (loop);
    return 0;
}
