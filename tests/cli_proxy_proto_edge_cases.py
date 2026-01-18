#!/usr/bin/env python3
import socket
import subprocess
import time
import sys
import os

def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def run_multi_header_test(nc_path: str) -> None:
    port = free_tcp_port()
    # Server with --proxy-proto and -v
    server_cmd = [nc_path, "-v", "-l", "127.0.0.1", str(port), "--proxy-proto"]
    
    server = subprocess.Popen(
        server_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    time.sleep(0.5)

    with socket.create_connection(("127.0.0.1", port)) as s:
        # Send two v1 headers
        header1 = b"PROXY TCP4 1.1.1.1 2.2.2.2 1111 2222\r\n"
        header2 = b"PROXY TCP4 3.3.3.3 4.4.4.4 3333 4444\r\n"
        payload = b"actual data\n"
        s.sendall(header1 + header2 + payload)
        time.sleep(0.5)

    server.terminate()
    out, err = server.communicate(timeout=2)
    
    print(f"Server stderr:\n{err}")
    print(f"Server stdout: {repr(out)}")

    # Check that first header was parsed
    if "PROXY v1: 1.1.1.1:1111 -> 2.2.2.2:2222" not in err:
        raise RuntimeError("First header not parsed correctly")
    
    # Check that second header appeared in stdout (as data)
    # Be liberal with line endings
    h2_clean = "PROXY TCP4 3.3.3.3 4.4.4.4 3333 4444"
    if h2_clean not in out:
        raise RuntimeError("Second header not found in payload")
    if "actual data" not in out:
        raise RuntimeError("Payload not found in payload")

    print("Multi-header test passed!")

def run_disabled_test(nc_path: str) -> None:
    port = free_tcp_port()
    # Server WITHOUT --proxy-proto
    server_cmd = [nc_path, "-l", "127.0.0.1", str(port)]
    
    server = subprocess.Popen(
        server_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    time.sleep(0.5)

    with socket.create_connection(("127.0.0.1", port)) as s:
        header = b"PROXY TCP4 1.1.1.1 2.2.2.2 1111 2222\r\n"
        payload = b"actual data\n"
        s.sendall(header + payload)
        time.sleep(0.5)

    server.terminate()
    out, err = server.communicate(timeout=2)
    
    print(f"Disabled test stdout: {repr(out)}")

    if "PROXY TCP4 1.1.1.1 2.2.2.2 1111 2222" not in out:
        raise RuntimeError("Header not treated as payload when feature disabled")
    
    print("Disabled feature test passed!")

def main() -> int:
    nc_path = sys.argv[1]
    run_multi_header_test(nc_path)
    run_disabled_test(nc_path)
    return 0

if __name__ == "__main__":
    sys.exit(main())
