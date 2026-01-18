#!/usr/bin/env python3
import argparse
import socket
import subprocess
import sys
import time

def run_fuzzer_test(nc_path: str) -> None:
    # Use a TCP server to receive fuzzed data
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        
        # Start client with --fuzz-tcp
        client_cmd = [nc_path, "--fuzz-tcp", "127.0.0.1", str(port)]
        client = subprocess.Popen(client_cmd)
        
        try:
            conn, addr = s.accept()
            conn.settimeout(5.0)
            data = conn.recv(1024)
            if len(data) > 0:
                print(f"Fuzzer sent {len(data)} bytes of data")
            else:
                raise RuntimeError("Fuzzer sent no data")
            conn.close()
        finally:
            client.kill()
            client.communicate()

    # Use a UDP server to receive fuzzed data
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        
        # Start client with --fuzz-udp
        client_cmd = [nc_path, "--fuzz-udp", "-u", "127.0.0.1", str(port)]
        client = subprocess.Popen(client_cmd)
        
        try:
            s.settimeout(5.0)
            data, addr = s.recvfrom(1024)
            if len(data) > 0:
                print(f"Fuzzer sent {len(data)} bytes of UDP data")
            else:
                raise RuntimeError("Fuzzer sent no UDP data")
        finally:
            client.kill()
            client.communicate()
            
    print("Fuzzer test passed!")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("nc_path")
    args = parser.parse_args()
    try:
        run_fuzzer_test(args.nc_path)
    except Exception as e:
        print(f"Test failed: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
