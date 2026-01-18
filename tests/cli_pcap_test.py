#!/usr/bin/env python3
import argparse
import select
import socket
import subprocess
import sys
import time
import os
import struct

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
        if "Listening" in line or "listening" in line or "Bound" in line or "bound" in line:
            return collected
    raise RuntimeError(f"listener did not become ready; stderr so far:\n{collected}")

def verify_pcap(path):
    if not os.path.exists(path):
        raise RuntimeError(f"PCAP file {path} does not exist")
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic != b"\xd4\xc3\xb2\xa1":
             raise RuntimeError(f"Invalid PCAP magic: {magic.hex()}")
        f.seek(0, 2)
        size = f.tell()
        if size <= 24:
             raise RuntimeError(f"PCAP file is too small: {size} bytes")
    print(f"Verified PCAP file {path}, size: {size} bytes")

def run_pcap_test_tcp(nc_path: str) -> None:
    port = free_tcp_port()
    pcap_path = "test_tcp.pcap"
    if os.path.exists(pcap_path):
        os.remove(pcap_path)

    # Server with PCAP
    server_cmd = [nc_path, "-v", "-l", "127.0.0.1", str(port), "-N", "--pcap", pcap_path]
    
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

    client.stdin.write("ping\n")
    client.stdin.flush()
    client.stdin.close()

    server.stdin.write("pong\n")
    server.stdin.flush()
    server.stdin.close()

    client.communicate(timeout=5)
    server.communicate(timeout=5)

    verify_pcap(pcap_path)
    os.remove(pcap_path)

def run_pcap_test_udp(nc_path: str) -> None:
    port = free_tcp_port()
    pcap_path = "test_udp.pcap"
    if os.path.exists(pcap_path):
        os.remove(pcap_path)

    # Server with PCAP
    server_cmd = [nc_path, "-u", "-v", "-l", "127.0.0.1", str(port), "--pcap", pcap_path]
    
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
    client_cmd = [nc_path, "-u", "127.0.0.1", str(port)]
    client = subprocess.Popen(
        client_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    client.stdin.write("ping\n")
    client.stdin.flush()
    time.sleep(0.5)
    
    server.stdin.write("pong\n")
    server.stdin.flush()
    time.sleep(0.5)

    client.kill()
    server.kill()

    verify_pcap(pcap_path)
    os.remove(pcap_path)

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("nc_path")
    args = parser.parse_args()
    print("Testing TCP PCAP...")
    run_pcap_test_tcp(args.nc_path)
    print("Testing UDP PCAP...")
    run_pcap_test_udp(args.nc_path)
    return 0

if __name__ == "__main__":
    sys.exit(main())