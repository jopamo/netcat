project('netcat', 'c',
  version : '1.226',
  default_options : ['c_std=gnu17', 'warning_level=2'])

cc = meson.get_compiler('c')

# Dependencies
# libresolv is often needed for b64_ntop and DNS
libresolv = cc.find_library('resolv', required : false)

deps = []
add_project_arguments('-D_GNU_SOURCE', language : 'c')

threads = dependency('threads')
deps += threads

if libresolv.found()
  deps += libresolv
endif

# TLS is provided by the vendored mbedtls backend.

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
    warning('Kernel version ' + kv + ' is older than 5.10. io_uring might not be supported.')
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

mbedtls_inc = include_directories(
  '.',
  'mbedtls/include',
  'mbedtls/library',
  'mbedtls/tf-psa-crypto/include',
  'mbedtls/tf-psa-crypto/core',
  'mbedtls/tf-psa-crypto/drivers/builtin/include',
  'mbedtls/tf-psa-crypto/drivers/builtin/src',
)
mbedtls_libdir = join_paths(meson.current_source_dir(), 'mbedtls', 'library')
tfpsa_core_dir = join_paths(meson.current_source_dir(), 'mbedtls', 'tf-psa-crypto', 'core')
tfpsa_drv_dir = join_paths(meson.current_source_dir(), 'mbedtls', 'tf-psa-crypto', 'drivers', 'builtin', 'src')
mbedtls_srcs = run_command(
  'python3',
  '-c',
  'import os,sys; d0,d1,d2=sys.argv[1:]; files=[];'
  + 'files+= [os.path.join("mbedtls","library",f) for f in os.listdir(d0) if f.endswith(".c")];'
  + 'files+= [os.path.join("mbedtls","tf-psa-crypto","core",f) for f in os.listdir(d1) if f.endswith(".c")];'
  + 'files+= [os.path.join("mbedtls","tf-psa-crypto","drivers","builtin","src",f) for f in os.listdir(d2) if f.endswith(".c")];'
  + 'print(" ".join(sorted(files)))',
  mbedtls_libdir,
  tfpsa_core_dir,
  tfpsa_drv_dir,
  check : true
).stdout().strip().split()

tfpsa_driver_wrappers = custom_target(
  'tfpsa_driver_wrappers',
  output : ['psa_crypto_driver_wrappers.h', 'psa_crypto_driver_wrappers_no_static.c'],
  command : [
    'python3',
    join_paths(meson.current_source_dir(), 'mbedtls', 'tf-psa-crypto', 'scripts', 'generate_driver_wrappers.py'),
    meson.current_build_dir(),
  ],
  depend_files : [
    'mbedtls/tf-psa-crypto/scripts/generate_driver_wrappers.py',
    'mbedtls/tf-psa-crypto/scripts/data_files/driver_templates/psa_crypto_driver_wrappers.h.jinja',
    'mbedtls/tf-psa-crypto/scripts/data_files/driver_templates/psa_crypto_driver_wrappers_no_static.c.jinja',
  ],
  build_by_default : true,
)

tfpsa_config_checks = custom_target(
  'tfpsa_config_checks',
  output : [
    'tf_psa_crypto_config_check_before.h',
    'tf_psa_crypto_config_check_user.h',
    'tf_psa_crypto_config_check_final.h',
  ],
  command : [
    'python3',
    join_paths(meson.current_source_dir(), 'mbedtls', 'tf-psa-crypto', 'scripts', 'generate_config_checks.py'),
    meson.current_build_dir(),
  ],
  depend_files : [
    'mbedtls/tf-psa-crypto/scripts/generate_config_checks.py',
    'mbedtls/tf-psa-crypto/framework/scripts/mbedtls_framework/config_checks_generator.py',
  ],
  build_by_default : true,
)

mbedtls_config_checks = custom_target(
  'mbedtls_config_checks',
  output : [
    'mbedtls_config_check_before.h',
    'mbedtls_config_check_user.h',
    'mbedtls_config_check_final.h',
  ],
  command : [
    'python3',
    join_paths(meson.current_source_dir(), 'mbedtls', 'scripts', 'generate_config_checks.py'),
    meson.current_build_dir(),
  ],
  depend_files : [
    'mbedtls/scripts/generate_config_checks.py',
    'mbedtls/framework/scripts/mbedtls_framework/config_checks_generator.py',
  ],
  build_by_default : true,
)

mbedtls_error_c = custom_target(
  'mbedtls_error_c',
  output : ['error.c'],
  command : [
    'perl',
    join_paths(meson.current_source_dir(), 'mbedtls', 'scripts', 'generate_errors.pl'),
    join_paths(meson.current_source_dir(), 'mbedtls', 'tf-psa-crypto', 'drivers', 'builtin', 'include', 'mbedtls'),
    join_paths(meson.current_source_dir(), 'mbedtls', 'include', 'mbedtls'),
    join_paths(meson.current_source_dir(), 'mbedtls', 'scripts', 'data_files'),
    '@OUTPUT@',
  ],
  depend_files : [
    'mbedtls/scripts/generate_errors.pl',
    'mbedtls/scripts/data_files/error.fmt',
  ],
  build_by_default : true,
)

mbedtls_version_features_c = custom_target(
  'mbedtls_version_features_c',
  output : ['version_features.c'],
  command : [
    'perl',
    join_paths(meson.current_source_dir(), 'mbedtls', 'scripts', 'generate_features.pl'),
    join_paths(meson.current_source_dir(), 'mbedtls', 'include', 'mbedtls'),
    join_paths(meson.current_source_dir(), 'mbedtls', 'scripts', 'data_files'),
    '@OUTPUT@',
  ],
  depend_files : [
    'mbedtls/scripts/generate_features.pl',
    'mbedtls/scripts/data_files/version_features.fmt',
  ],
  build_by_default : true,
)

mbedtls_ssl_debug_helpers_c = custom_target(
  'mbedtls_ssl_debug_helpers_c',
  output : ['ssl_debug_helpers_generated.c'],
  command : [
    'python3',
    join_paths(meson.current_source_dir(), 'mbedtls', 'framework', 'scripts', 'generate_ssl_debug_helpers.py'),
    '--mbedtls-root',
    join_paths(meson.current_source_dir(), 'mbedtls'),
    meson.current_build_dir(),
  ],
  depend_files : [
    'mbedtls/framework/scripts/generate_ssl_debug_helpers.py',
  ],
  build_by_default : true,
)

mbedtls_srcs += [
  tfpsa_driver_wrappers,
  tfpsa_config_checks,
  mbedtls_config_checks,
  mbedtls_error_c,
  mbedtls_version_features_c,
  mbedtls_ssl_debug_helpers_c,
]
mbedtls_lib = static_library('mbedtls',
  mbedtls_srcs,
  include_directories : mbedtls_inc,
)

inc = include_directories(
  'src',
  '.',
  'mbedtls/include',
  'mbedtls/library',
  'mbedtls/tf-psa-crypto/include',
  'mbedtls/tf-psa-crypto/core',
  'mbedtls/tf-psa-crypto/drivers/builtin/include',
  'mbedtls/tf-psa-crypto/drivers/builtin/src',
)

nc_bin = executable('nc',
  srcs,
  include_directories : [inc, mbedtls_inc],
  dependencies : deps,
  link_with : [mbedtls_lib],
  install : true)

install_man('man/nc.1')

subdir('tests')
