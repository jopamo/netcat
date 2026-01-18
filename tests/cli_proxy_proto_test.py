#!/usr/bin/env python3
import argparse
import select
import socket
import subprocess
import sys
import time
import os

def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def wait_for_listening(proc: subprocess.Popen, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    collected = ""
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        rlist, _, _ = select.select([proc.stderr], [], [], remaining)
        if proc.poll() is not None:
            break
        if not rlist:
            continue
        line = proc.stderr.readline()
        if not line:
            continue
        collected += line
        if "Listening" in line:
            return collected
    raise RuntimeError(f"listener did not become ready; stderr so far:\n{collected}")

def run_proxy_proto_test(nc_path: str) -> None:
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

    try:
        wait_for_listening(server, timeout=3.0)
    except Exception:
        server.kill()
        raise

    # Client with --send-proxy
    client_cmd = [nc_path, "127.0.0.1", str(port), "--send-proxy"]
    client = subprocess.Popen(
        client_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    client.stdin.write("hello\n")
    client.stdin.flush()
    time.sleep(0.5)
    
    # Check if client is still running
    if client.poll() is not None:
        print("Client exited early!")
        print(f"Client stderr: {client.stderr.read()}")
    
    client.kill()
    server.kill()

    _, err_server = server.communicate()
    
    print(f"Server stderr:\n{err_server}")
    if "PROXY v2:" not in err_server:
        raise RuntimeError("Server did not log PROXY v2 info")
    print("Proxy Protocol v2 test passed!")

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("nc_path")
    args = parser.parse_args()
    run_proxy_proto_test(args.nc_path)
    return 0

if __name__ == "__main__":
    sys.exit(main())
