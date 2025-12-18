#!/usr/bin/env python3
import argparse
import socket
import subprocess
import sys
import time


def free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_udp_loopback(nc_path: str) -> None:
    port = free_udp_port()

    server = subprocess.Popen(
        [nc_path, "-u", "-v", "-l", "-p", str(port), "-q", "1"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    # Give listener a moment to bind (UDP has no listen backlog). Minimal sleep avoids flaky readiness detection.
    time.sleep(0.2)

    client = subprocess.Popen(
        [nc_path, "-u", "127.0.0.1", str(port), "-q", "1"],
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

    if client.returncode != 0 or server.returncode != 0:
        raise RuntimeError(
            f"nc exited nonzero: client={client.returncode}, server={server.returncode}\n"
            f"client stderr: {err_client}\nserver stderr: {err_server}"
        )

    if out_server != "ping\n":
        raise RuntimeError(f"UDP listener did not receive ping: {out_server!r}")
    if out_client != "pong\n":
        raise RuntimeError(f"UDP client did not receive pong: {out_client!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("nc_path")
    args = parser.parse_args()
    run_udp_loopback(args.nc_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
