project('netcat', 'c', version:'1.10', default_options:['c_std=c17', 'warning_level=3'])

cc = meson.get_compiler('c')

add_project_arguments('-D_GNU_SOURCE', '-DHAVE_BIND', '-DHAVE_HELP', language:'c')

if get_option('ipv6')
  add_project_arguments('-DINET6', language:'c')
endif
if get_option('telnet')
  add_project_arguments('-DTELNET', language:'c')
endif
if get_option('verbose_debug')
  add_project_arguments('-DDEBUG', language:'c')
endif
if get_option('exec_hole')
  add_project_arguments('-DGAPING_SECURITY_HOLE', language:'c')
endif

deps = []
libresolv = cc.find_library('resolv', required:false)
if libresolv.found()
  deps += libresolv
endif
libm = cc.find_library('m', required:false)
if libm.found()
  deps += libm
endif

executable(
  'nc',
  'netcat.c',
  include_directories: include_directories('.'),
  dependencies: deps,
  install: true
)

scripts = files(
  'scripts/bsh',
  'scripts/dist.sh',
  'scripts/irc',
  'scripts/iscan',
  'scripts/ncp',
  'scripts/probe',
  'scripts/web',
  'scripts/webproxy',
  'scripts/webrelay'
)
install_data(scripts, install_dir:get_option('bindir'), install_mode:'rwxr-xr-x')

install_man('nc.1')

docdir = get_option('datadir') / 'doc' / meson.project_name()
install_data(['README', 'README.md'], install_dir:docdir)

summary({
  'IPv6 support'        : get_option('ipv6'),
  'TELNET negotiation'  : get_option('telnet'),
  'Verbose DEBUG macros': get_option('verbose_debug'),
  'Exec (-e/-c) enabled': get_option('exec_hole'),
  'Linked with resolv'  : libresolv.found(),
  'Linked with libm'    : libm.found(),
}, bool_yn:true)
