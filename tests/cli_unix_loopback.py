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


def run_unix_loopback(nc_path: str) -> None:
    path = "/tmp/nc_test_socket_" + str(os.getpid())
    if os.path.exists(path):
        os.unlink(path)
    
    # Server: -l -U [path] -v -N
    server_cmd = [nc_path, "-v", "-l", "-U", path, "-N"]
    
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

    # Client: -U [path] -N
    client_cmd = [nc_path, "-U", "-N", path]
    
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
    client.stdin.close()

    server.stdin.write("pong\n")
    server.stdin.flush()
    server.stdin.close()

    out_client, err_client = client.communicate(timeout=5)
    out_server, err_server = server.communicate(timeout=5)

    if os.path.exists(path):
        os.unlink(path)

    if client.returncode != 0 or server.returncode != 0:
        raise RuntimeError(
            f"nc exited nonzero: client={client.returncode}, server={server.returncode}\n"
            f"client stderr: {err_client}\nserver stderr: {err_server}"
        )

    if out_server != "ping\n":
        raise RuntimeError(f"listener did not receive ping: {out_server!r}")
    if out_client != "pong\n":
        raise RuntimeError(f"client did not receive pong: {out_client!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("nc_path")
    args = parser.parse_args()
    try:
        run_unix_loopback(args.nc_path)
    except Exception as e:
        print(f"Test failed: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
