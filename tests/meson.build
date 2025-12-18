python = import('python')
python3 = python.find_installation()

test_includes = nc_includes

resolve_test = executable(
  'resolve_test',
  ['resolve_test.c', '../src/resolve.c', '../src/nc_ctx.c'],
  include_directories: test_includes,
  dependencies: deps,
)
test('port_parsing_and_randomization', resolve_test)

telnet_test = executable(
  'telnet_test',
  ['telnet_test.c', '../src/telnet.c', '../src/nc_ctx.c'],
  include_directories: test_includes,
  dependencies: deps,
)
test('telnet_negotiation_replies', telnet_test)

io_pump_test = executable(
  'io_pump_test',
  ['io_pump_test.c', '../src/io_pump.c', '../src/hexdump.c', '../src/telnet.c', '../src/nc_ctx.c'],
  include_directories: test_includes,
  dependencies: deps,
)
test('io_pump_bidirectional_transfer', io_pump_test)

udp_listen_test = executable(
  'udp_listen_test',
  ['udp_listen_test.c', '../src/connect.c', '../src/resolve.c', '../src/nc_ctx.c'],
  include_directories: test_includes,
  dependencies: deps,
)
test('udp_accept_and_lock_peer', udp_listen_test)

test('cli_tcp_loopback',
     python3,
     args: [files('cli_tcp_loopback.py'), nc_bin.full_path()],
     should_fail: false)
test('cli_udp_loopback',
     python3,
     args: [files('cli_udp_loopback.py'), nc_bin.full_path()],
     should_fail: false)
test('cli_connect_timeout',
     python3,
     args: [files('cli_connect_timeout.py'), nc_bin.full_path()],
     should_fail: false)
test('cli_interval_pacing',
     python3,
     args: [files('cli_interval_pacing.py'), nc_bin.full_path()],
     should_fail: false)
test('cli_udp_interval_pacing',
     python3,
     args: [files('cli_udp_interval_pacing.py'), nc_bin.full_path()],
     should_fail: false)
test('cli_quit_after_eof',
     python3,
     args: [files('cli_quit_after_eof.py'), nc_bin.full_path()],
     should_fail: false)
test('cli_udp_quit_after_eof',
     python3,
     args: [files('cli_udp_quit_after_eof.py'), nc_bin.full_path()],
     should_fail: false)
test('cli_documents_removed_source_routing',
     python3,
     args: [files('doc_source_routing_removed.py'), nc_bin.full_path()],
     should_fail: false)

if get_option('exec_hole')
  exec_helper = executable(
    'exec_helper',
    ['exec_helper.c'],
    include_directories: test_includes,
    dependencies: deps,
  )

  test('cli_exec_argv',
       python3,
       args: [files('cli_exec_features.py'), nc_bin.full_path(), exec_helper.full_path(), '--case', 'exec-argv'],
       should_fail: false)
  test('cli_exec_closes_extra_fds',
       python3,
       args: [files('cli_exec_features.py'), nc_bin.full_path(), exec_helper.full_path(), '--case', 'close-fds'],
       should_fail: false)
  test('cli_exec_inherit_fds',
       python3,
       args: [files('cli_exec_features.py'), nc_bin.full_path(), exec_helper.full_path(), '--case', 'inherit-fds'],
       should_fail: false)
  test('cli_exec_reset_signals',
       python3,
       args: [files('cli_exec_features.py'), nc_bin.full_path(), exec_helper.full_path(), '--case', 'reset-signals'],
       should_fail: false)
endif

if not ipv6_enabled
  test('cli_rejects_ipv6_flag_when_disabled',
       python3,
       args: [files('cli_failures.py'), nc_bin.full_path(), '--case', 'ipv6_disabled'],
       should_fail: false)
endif

if not get_option('exec_hole')
  test('cli_rejects_exec_flag_when_disabled',
       python3,
       args: [files('cli_failures.py'), nc_bin.full_path(), '--case', 'exec_disabled'],
       should_fail: false)
endif
