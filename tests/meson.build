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
