#!/usr/bin/env python3
import argparse
import select
import socket
import subprocess
import sys
import time


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
        if "Listening on" in line or "listening on" in line:
            return collected
    raise RuntimeError(f"listener did not become ready; stderr so far:\n{collected}")


def run_tcp_loopback(nc_path: str) -> None:
    port = free_tcp_port()
    # Server: -l [port] -v -N (shutdown on EOF)
    server_cmd = [nc_path, "-v", "-l", "127.0.0.1", str(port), "-N"]
    
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

    # Client: [ip] [port] -N
    client_cmd = [nc_path, "-N", "127.0.0.1", str(port)]
    
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
    # Close client stdin to trigger shutdown (due to -N)
    client.stdin.close()

    # Server receives ping, then EOF (shutdown), then sends pong, then closes?
    # Wait, -N on server means "Shutdown the network socket after EOF on stdin".
    # We want the server to READ ping, then WRITE pong, then close.
    # If we close client stdin, server gets EOF on socket.
    # Does server close immediately?
    # Netcat behavior: Read stdin -> send to net. Read net -> send to stdout.
    # If net gives EOF, netcat closes stdout and exits?
    
    # Let's verify standard loop:
    # Client writes 'ping', closes stdin (-N sends FIN).
    # Server reads 'ping' (to stdout), gets FIN.
    # Server writes 'pong' (to net).
    # Server closes stdin (-N sends FIN).
    
    server.stdin.write("pong\n")
    server.stdin.flush()
    server.stdin.close()

    out_client, err_client = client.communicate(timeout=5)
    out_server, err_server = server.communicate(timeout=5)

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
    run_tcp_loopback(args.nc_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
