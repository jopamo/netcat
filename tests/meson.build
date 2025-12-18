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
