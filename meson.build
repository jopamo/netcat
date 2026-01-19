project('netcat', 'c',
  version : '1.226',
  default_options : ['c_std=gnu17', 'warning_level=2'])

cc = meson.get_compiler('c')

# Dependencies
# libresolv is often needed for b64_ntop and DNS
libresolv = cc.find_library('resolv', required : false)

deps = []
add_project_arguments('-D_GNU_SOURCE', language : 'c')

if libresolv.found()
  deps += libresolv
endif

# Check for libtls (LibreSSL) or libretls
# We are replacing this with OpenSSL compat layer
openssl = dependency('openssl', required : true)
deps += openssl

# Math library
libm = cc.find_library('m', required : false)
if libm.found()
  deps += libm
endif

# liburing for asynchronous I/O
liburing = dependency('liburing', required : false)
if liburing.found()
  deps += liburing
  add_project_arguments('-DUSE_IO_URING', language : 'c')
endif

# libbpf for eBPF filter injection
libbpf = dependency('libbpf', required : false)
if libbpf.found()
  deps += libbpf
  add_project_arguments('-DHAVE_LIBBPF', language : 'c')
endif

# libcap for namespace/privilege operations
libcap = dependency('libcap', required : false)
if libcap.found()
  deps += libcap
  add_project_arguments('-DHAVE_LIBCAP', language : 'c')
endif

if host_machine.system() == 'linux'
  uname = find_program('uname')
  r = run_command(uname, '-r', check: true)
  kv = r.stdout().strip()
  if kv.version_compare('< 5.10')
    warning('Kernel version ' + kv + ' is older than 5.10. io_uring and KTLS might not be supported.')
  endif
endif

if get_option('security_hole')
  add_project_arguments('-DGAPING_SECURITY_HOLE', language : 'c')
endif

git = find_program('git', required : false)
git_hash = 'unknown'
git_date = 'unknown'
if git.found()
  r = run_command(git, 'rev-parse', '--short=12', 'HEAD', check : false)
  if r.returncode() == 0
    git_hash = r.stdout().strip()
  endif
  r = run_command(git, 'show', '-s', '--format=%cs', 'HEAD', check : false)
  if r.returncode() == 0
    git_date = r.stdout().strip()
  endif
endif

version_conf = configuration_data()
version_conf.set('NC_VERSION', meson.project_version())
version_conf.set('NC_GIT_HASH', git_hash)
version_conf.set('NC_GIT_DATE', git_date)
configure_file(input : 'src/version.h.in', output : 'version.h', configuration : version_conf)

srcs = [
  'src/netcat.c',
  'src/atomicio.c',
  'src/socks.c',
  'src/io.c',
  'src/network.c',
  'src/tls.c',
  'src/tls_compat.c',
  'src/utils.c',
  'src/log.c',
  'src/pcap.c',
  'src/proxy_proto.c',
  'src/hexdump.c',
  'src/quic.c',
  'src/bpf.c'
]

inc = include_directories('src', '.')

nc_bin = executable('nc',
  srcs,
  include_directories : inc,
  dependencies : deps,
  install : true)

install_man('man/nc.1')

subdir('tests')
