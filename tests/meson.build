python = import('python').find_installation('python3')

proxy_proto_test = executable('proxy_proto_test',
  ['proxy_proto_test.c', '../src/proxy_proto.c', '../src/atomicio.c', '../compat/openbsd_compat.c'],
  include_directories : inc,
  dependencies : deps)

test('proxy_proto_unit_test', proxy_proto_test)

atomicio_test = executable('atomicio_test',
  ['atomicio_test.c', '../src/atomicio.c'],
  include_directories : inc,
  dependencies : deps)

test('atomicio_unit_test', atomicio_test)

test('cli_socks_test',
     python,
     args: [files('cli_socks_test.py'), nc_bin],
     timeout: 15)

io_shaping_test = executable('io_shaping_test',
  ['io_shaping_test.c', '../src/io.c', '../src/utils.c', '../src/atomicio.c', '../src/log.c', '../compat/tls_compat.c', '../compat/openbsd_compat.c'],
  include_directories : inc,
  dependencies : deps)

test('io_shaping_unit_test', io_shaping_test)

test('cli_proxy_proto_edge_cases',
     python,
     args: [files('cli_proxy_proto_edge_cases.py'), nc_bin],
     timeout: 10)

test('cli_netpair_test',
     python,
     args: [files('cli_netpair_test.py'), nc_bin],
     timeout: 10)

test('cli_buffer_limits',
     python,
     args: [files('cli_buffer_limits.py'), nc_bin],
     timeout: 20)

test('cli_error_propagation',
     python,
     args: [files('cli_error_propagation.py'), nc_bin],
     timeout: 10)

test('cli_argument_test',
     python,
     args: [files('cli_argument_test.py'), nc_bin],
     timeout: 10)

test('cli_exec_test',
     python,
     args: [files('cli_exec_test.py'), nc_bin],
     timeout: 10)

test('cli_conflict_matrix',
     python,
     args: [files('cli_conflict_matrix.py'), nc_bin],
     timeout: 10)

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

test('cli_pcap_test',
     python,
     args: [files('cli_pcap_test.py'), nc_bin],
     timeout: 10)

test('cli_proxy_proto_test',
     python,
     args: [files('cli_proxy_proto_test.py'), nc_bin],
     timeout: 10)

test('cli_hexdump_test',
     python,
     args: [files('cli_hexdump_test.py'), nc_bin],
     timeout: 10)

test('cli_dtls_test',
     python,
     args: [files('cli_dtls_test.py'), nc_bin],
     timeout: 20)

test('cli_quic_probe',
     python,
     args: [files('cli_quic_probe.py'), nc_bin],
     timeout: 10)

test('cli_bpf_test',
     python,
     args: [files('cli_bpf_test.py'), nc_bin],
     timeout: 10)

utils_test = executable('utils_test',
  ['utils_simple_test.c', '../src/utils.c', '../compat/openbsd_compat.c'],
  include_directories : inc,
  dependencies : deps)

test('utils_unit_test', utils_test)

bpf_failure_test = executable('bpf_failure_test',
  ['bpf_failure_test.c', '../src/bpf.c', '../src/log.c', '../compat/openbsd_compat.c'],
  include_directories : inc,
  dependencies : deps)

test('bpf_failure_unit_test', bpf_failure_test)

tls_conceptual_test = executable('tls_conceptual_test',
  ['tls_conceptual_test.c'],
  include_directories : inc,
  dependencies : [])

test('tls_conceptual_unit_test', tls_conceptual_test)
