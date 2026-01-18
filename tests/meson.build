python = import('python').find_installation('python3')

test('cli_tcp_loopback',
     python,
     args: [files('cli_tcp_loopback.py'), nc_bin],
     timeout: 10)

test('cli_udp_loopback',
     python,
     args: [files('cli_udp_loopback.py'), nc_bin],
     timeout: 10)

test('cli_connect_timeout',
     python,
     args: [files('cli_connect_timeout.py'), nc_bin],
     timeout: 10)

test('cli_unix_loopback',
     python,
     args: [files('cli_unix_loopback.py'), nc_bin],
     timeout: 10)

test('cli_abstract_unix_loopback',
     python,
     args: [files('cli_abstract_unix_loopback.py'), nc_bin],
     timeout: 10)

test('cli_abstract_unix_udp_loopback',
     python,
     args: [files('cli_abstract_unix_udp_loopback.py'), nc_bin],
     timeout: 10)

test('cli_json_output',
     python,
     args: [files('cli_json_output.py'), nc_bin],
     timeout: 10)

test('cli_fuzzer',
     python,
     args: [files('cli_fuzzer.py'), nc_bin],
     timeout: 10)
