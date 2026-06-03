// SPDX-License-Identifier: GPL-3.0-or-later
/* Vala binding for the mtproxy-ws C engine (proxy.h). */
namespace TgWsProxy {

    [Compact]
    [CCode (cname = "TgwsProxy", cheader_filename = "proxy.h",
            free_function = "tgws_proxy_free")]
    public class Engine {
        [CCode (cname = "tgws_proxy_new")]
        public Engine (string host, uint16 port,
                       [CCode (array_length = false)] uint8[] secret16);

        [CCode (cname = "tgws_proxy_add_dc")]
        public void add_dc (int dc, string ip);

        [CCode (cname = "tgws_proxy_set_cfproxy")]
        public void set_cfproxy (bool enabled);
        [CCode (cname = "tgws_proxy_set_verify_cf")]
        public void set_verify_cf (bool enabled);
        [CCode (cname = "tgws_proxy_add_cf_domain")]
        public void add_cf_domain (string domain);
        [CCode (cname = "tgws_proxy_add_worker_domain")]
        public void add_worker_domain (string domain);
        [CCode (cname = "tgws_proxy_set_fake_tls")]
        public void set_fake_tls (string domain);
        [CCode (cname = "tgws_proxy_set_pool_size")]
        public void set_pool_size (int size);

        [CCode (cname = "tgws_proxy_start")]
        public bool start ();

        [CCode (cname = "tgws_proxy_stop")]
        public void stop ();

        [CCode (cname = "tgws_proxy_connections_total")]
        public int64 connections_total ();
        [CCode (cname = "tgws_proxy_connections_active")]
        public int64 connections_active ();
        [CCode (cname = "tgws_proxy_bytes_up")]
        public int64 bytes_up ();
        [CCode (cname = "tgws_proxy_bytes_down")]
        public int64 bytes_down ();
    }

    [CCode (cname = "tgws_engine_selftest", cheader_filename = "proxy.h")]
    public int engine_selftest ();
}