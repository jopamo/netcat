project('netcat', 'c',
  version : '1.226',
  default_options : ['c_std=gnu17', 'warning_level=2'])

cc = meson.get_compiler('c')

# Dependencies
# libbsd is required for OpenBSD compatibility on Linux (strlcpy, readpassphrase, etc.)
libbsd = dependency('libbsd', required : false)
if not libbsd.found()
  # Try to find it via cc.find_library if pkg-config fails, though unlikely for libbsd
  libbsd = cc.find_library('bsd', required : false)
endif

# libresolv is often needed for b64_ntop and DNS
libresolv = cc.find_library('resolv', required : false)

deps = []
if libbsd.found()
  deps += libbsd
  add_project_arguments('-D_GNU_SOURCE', language : 'c')
endif

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

# Check for readpassphrase.h location
if cc.has_header('bsd/readpassphrase.h')
  add_project_arguments('-DHAVE_BSD_READPASSPHRASE_H', language : 'c')
elif cc.has_header('readpassphrase.h')
  add_project_arguments('-DHAVE_READPASSPHRASE_H', language : 'c')
else
   if libbsd.found()
      warning('readpassphrase.h not found but libbsd found. Assuming bsd/readpassphrase.h might work if paths were correct, but proceeding without definition.')
   else
      warning('readpassphrase.h not found. Compilation will likely fail.')
   endif
endif

srcs = [
  'src/netcat.c',
  'src/atomicio.c',
  'src/socks.c',
  'src/io.c',
  'src/network.c',
  'src/tls.c',
  'src/utils.c',
  'src/log.c',
  'src/pcap.c',
  'src/proxy_proto.c',
  'src/hexdump.c',
  'src/quic.c',
  'src/bpf.c',
  'compat/tls_compat.c',
  'compat/openbsd_compat.c'
]

inc = include_directories('src', 'compat')

nc_bin = executable('nc',
  srcs,
  include_directories : inc,
  dependencies : deps,
  install : true)

install_man('man/nc.1')

subdir('tests')