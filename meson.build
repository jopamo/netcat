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
  'netcat.c',
  'atomicio.c',
  'socks.c',
  'compat/tls_compat.c',
  'compat/openbsd_compat.c'
]

inc = include_directories('.', 'compat')

executable('nc',
  srcs,
  include_directories : inc,
  dependencies : deps,
  install : true)

install_man('nc.1')