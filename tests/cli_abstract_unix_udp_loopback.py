#!/usr/bin/env python3
import argparse
import select
import socket
import subprocess
import sys
import time
import os

def wait_for_listening(proc: subprocess.Popen, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    collected = ""
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        rlist, _, _ = select.select([proc.stderr], [], [], remaining)
        if proc.poll() is not None:
            break
        if not rlist:
            continue
        line = proc.stderr.readline()
        if not line:
            continue
        collected += line
        if "Bound" in line or "Listening" in line:
            return collected
    raise RuntimeError(f"listener did not become ready; stderr so far:\n{collected}")


def run_abstract_unix_udp_loopback(nc_path: str) -> None:
    if sys.platform != "linux":
        print("Abstract unix sockets only supported on Linux")
        return

    server_socket = "@nc_test_udp_server_" + str(os.getpid())
    client_socket = "@nc_test_udp_client_" + str(os.getpid())
    
    # Server: -l -U -u [path] -v
    server_cmd = [nc_path, "-v", "-l", "-U", "-u", server_socket]
    
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

    # Client: -U -u -s [client_path] [server_path]
    client_cmd = [nc_path, "-U", "-u", "-s", client_socket, server_socket]
    
    client = subprocess.Popen(
        client_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert client.stdin is not None
    assert server.stdin is not None

    client.stdin.write("ping\n")
    client.stdin.flush()
    
    # Wait a bit for server to receive and print
    time.sleep(0.5)

    server.stdin.write("pong\n")
    server.stdin.flush()
    
    time.sleep(0.5)
    
    client.kill()
    server.kill()

    out_client, err_client = client.communicate()
    out_server, err_server = server.communicate()

    if "ping\n" not in out_server:
        raise RuntimeError(f"listener did not receive ping: {out_server!r}\nserver stderr: {err_server}\nclient stderr: {err_client}")
    if "pong\n" not in out_client:
        raise RuntimeError(f"client did not receive pong: {out_client!r}\nserver stderr: {err_server}\nclient stderr: {err_client}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("nc_path")
    args = parser.parse_args()
    try:
        run_abstract_unix_udp_loopback(args.nc_path)
    except Exception as e:
        print(f"Test failed: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
