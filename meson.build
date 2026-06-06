# mtproxy-ws — self-contained C package: the MTProto<->WebSocket proxy engine as
# a shared library, a headless CLI, and a Vala binding. Pure C, no GTK/Vala.
project('mtproxy-ws', 'c',
  version: '2.0.0',
  meson_version: '>= 0.62',
  default_options: ['warning_level=2', 'c_std=gnu11'],
  license: 'GPL-3.0-or-later',
)

cc = meson.get_compiler('c')

core_deps = [
  dependency('glib-2.0'),
  dependency('gio-2.0'),
  cc.find_library('crypto'),   # OpenSSL libcrypto (AES-CTR, SHA256, HMAC, RAND)
  cc.find_library('ssl'),      # OpenSSL libssl (TLS to the DC IP)
]
if host_machine.system() == 'windows'
  core_deps += cc.find_library('ws2_32')   # Winsock (sockets, WSAPoll)
endif
core_inc = include_directories('src')

# ELF visibility gates the ABI on POSIX (TGWS_PUBLIC == visibility default). On
# Windows TGWS_PUBLIC is empty and mingw auto-exports, so keep symbols visible.
symbol_visibility = host_machine.system() == 'windows' ? 'default' : 'hidden'

libmtproxyws = library('mtproxyws',
  'src/crypto.c',
  'src/net.c',
  'src/mtproto.c',
  'src/splitter.c',
  'src/websocket.c',
  'src/fake_tls.c',
  'src/client_io.c',
  'src/pool.c',
  'src/bridge.c',
  'src/proxy.c',
  dependencies: core_deps,
  include_directories: core_inc,
  version: meson.project_version(),
  # Hidden by default: only TGWS_PUBLIC-marked symbols leave the .so.
  gnu_symbol_visibility: symbol_visibility,
  install: true,
)

install_headers('src/proxy.h', 'src/crypto.h', subdir: 'mtproxy-ws')

pkgconfig = import('pkgconfig')
pkgconfig.generate(libmtproxyws,
  name: 'mtproxy-ws',
  description: 'Telegram MTProto <-> WebSocket bridge proxy engine',
  subdirs: 'mtproxy-ws',
  requires: ['glib-2.0', 'gio-2.0'],
  # Expose the Vala binding location so consumers can add it to --vapidir.
  variables: ['vapidir=${prefix}/' + get_option('datadir') / 'vala' / 'vapi'],
)

# Vala binding ships with the library (conventional): vapi + .deps in vapidir.
install_data('mtproxy-ws.vapi',
  install_dir: get_option('datadir') / 'vala' / 'vapi')
install_data('mtproxy-ws.deps',
  install_dir: get_option('datadir') / 'vala' / 'vapi')

# Usable as a meson subproject (e.g. the Android build pulls the core via a wrap):
# the vapidir variable lets the consumer add mtproxy-ws.vapi to valac's path.
mtproxyws_dep = declare_dependency(
  link_with: libmtproxyws,
  include_directories: core_inc,
  dependencies: core_deps,
  variables: {'vapidir': meson.current_source_dir()},
)
meson.override_dependency('mtproxy-ws', mtproxyws_dep)

# The standalone CLI + systemd service are only meaningful when mtproxy-ws is the
# top-level project. As a subproject (the Android GUI embeds the engine) we want
# the library alone — skip the CLI (and its install) and the unit. The CLI's
# signal handling is POSIX-only, so it is also skipped on Windows (the GUI ships
# its own headless --proxy mode there).
if not meson.is_subproject() and host_machine.system() != 'windows'

# Standalone headless CLI.
executable('mtproxy-ws',
  'src/cli.c',
  link_with: libmtproxyws,
  dependencies: [dependency('glib-2.0'), dependency('gio-2.0')],
  include_directories: core_inc,
  install: true,
)

# Optional systemd system service for the standalone proxy (opt-in).
if get_option('service')
  svc_conf = configuration_data()
  svc_conf.set('bindir', get_option('prefix') / get_option('bindir'))
  svc_conf.set('sysconfdir', get_option('prefix') / get_option('sysconfdir'))

  systemd = dependency('systemd', required: false)
  if systemd.found()
    unitdir = systemd.get_variable(pkgconfig: 'systemd_system_unit_dir',
                                   default_value: get_option('prefix') / 'lib' / 'systemd' / 'system')
  else
    unitdir = get_option('prefix') / 'lib' / 'systemd' / 'system'
  endif

  configure_file(
    input: 'data/mtproxy-ws.service.in',
    output: 'mtproxy-ws.service',
    configuration: svc_conf,
    install: true,
    install_dir: unitdir,
  )
  install_data('data/mtproxy-ws.conf.example',
    install_dir: get_option('datadir') / 'doc' / 'mtproxy-ws')
endif

endif  # not meson.is_subproject()
