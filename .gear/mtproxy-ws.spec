%define sover 2

Name:           mtproxy-ws
Version:        2.0.0
Release:        alt1

Summary:        MTProto <-> WebSocket Telegram proxy engine
License:        GPL-3.0-or-later
Group:          System/Libraries
URL:            https://github.com/Another-TGProxy/mtproxy-ws

Vcs:            https://github.com/Another-TGProxy/mtproxy-ws.git

Source0:        %name-%version.tar

BuildRequires(pre): rpm-macros-meson
BuildRequires: meson
BuildRequires: gcc
BuildRequires: pkgconfig(gio-2.0)
BuildRequires: libssl-devel
BuildRequires: pkgconfig(systemd)

%description
mtproxy-ws is a Telegram MTProto proxy that speaks WebSocket, bridging MTProto
clients to Telegram data centres while wrapping the transport in a WebSocket and
fake-TLS envelope. This source builds the engine shared library, its development
files and a standalone headless CLI with a systemd service.

%package -n libmtproxyws%{sover}
Summary:        MTProto <-> WebSocket proxy engine (shared library)
Group:          System/Libraries

%description -n libmtproxyws%{sover}
The mtproxy-ws engine as a shared library: MTProto framing, the obfuscated and
fake-TLS transport, WebSocket bridging and the connection pool.

%package -n libmtproxyws-devel
Summary:        Development files for libmtproxyws
Group:          Development/C
Requires:       libmtproxyws%{sover} = %version-%release

%description -n libmtproxyws-devel
Headers, pkg-config file and the Vala binding for building against the
mtproxy-ws engine.

%package -n mtproxy-ws-cli
Summary:        Standalone MTProto <-> WebSocket proxy CLI and service
Group:          Networking/Other
Requires:       libmtproxyws%{sover} = %version-%release

%description -n mtproxy-ws-cli
The headless mtproxy-ws command-line proxy and an opt-in systemd system service
for running it standalone, without the graphical front-end.

%prep
%setup

%build
%meson -Dservice=true
%meson_build

%install
%meson_install

%post -n mtproxy-ws-cli
%post_service mtproxy-ws

%preun -n mtproxy-ws-cli
%preun_service mtproxy-ws

%files -n libmtproxyws%{sover}
%doc LICENSE
%_libdir/libmtproxyws.so.%{sover}*

%files -n libmtproxyws-devel
%doc README.md
%_includedir/mtproxy-ws/
%_libdir/libmtproxyws.so
%_pkgconfigdir/mtproxy-ws.pc
%_datadir/vala/vapi/mtproxy-ws.vapi
%_datadir/vala/vapi/mtproxy-ws.deps

%files -n mtproxy-ws-cli
%_bindir/mtproxy-ws
%_unitdir/mtproxy-ws.service
%_datadir/doc/mtproxy-ws/mtproxy-ws.conf.example

%changelog
* Wed Jun 03 2026 Anton Politov <ampernic@altlinux.org> 2.0.0-alt1
- Initial build for ALT.

