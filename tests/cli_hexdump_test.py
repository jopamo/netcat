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

def run_hexdump_test(nc_path: str) -> None:
    port = free_tcp_port()
    hex_path = "test.hex"
    if os.path.exists(hex_path):
        os.remove(hex_path)
    
    # Server with --hex-dump
    server_cmd = [nc_path, "-v", "-l", "127.0.0.1", str(port), "-N", "--hex-dump", hex_path]
    
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

    # Client
    client_cmd = [nc_path, "-N", "127.0.0.1", str(port)]
    client = subprocess.Popen(
        client_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    client.stdin.write("Hello World\n")
    client.stdin.flush()
    client.stdin.close()

    server.stdin.write("Hi there\n")
    server.stdin.flush()
    server.stdin.close()

    client.communicate(timeout=5)
    server.communicate(timeout=5)

    if not os.path.exists(hex_path):
        raise RuntimeError("Hex dump file was not created")
    
    with open(hex_path, "r") as f:
        content = f.read()
        print(f"Hex dump content:\n{content}")
        if "> 00000000" not in content or "< 00000000" not in content:
            raise RuntimeError("Hex dump format incorrect")
        if "Hello World" not in content or "Hi there" not in content:
            raise RuntimeError("Hex dump missing expected data")

    print("Hex dump test passed!")
    os.remove(hex_path)

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("nc_path")
    args = parser.parse_args()
    run_hexdump_test(args.nc_path)
    return 0

if __name__ == "__main__":
    sys.exit(main())
