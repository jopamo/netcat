#!/usr/bin/env python3
import argparse
import socket
import subprocess
import sys
import time


def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_quit_after_eof(nc_path: str) -> None:
    port = free_tcp_port()
    server = subprocess.Popen(
        [nc_path, "-v", "-l", "-p", str(port), "-q", "2"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    start = time.monotonic()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    deadline = start + 3
    while True:
        try:
            sock.connect(("127.0.0.1", port))
            break
        except ConnectionRefusedError:
            if time.monotonic() > deadline:
                server.kill()
                raise RuntimeError("listener did not accept connections in time")
            time.sleep(0.05)

    # Trigger quit timer on server but keep network open for reading
    server.stdin.close()

    sock.sendall(b"hello\n")
    sock.shutdown(socket.SHUT_WR)

    line = server.stdout.readline()
    if line != "hello\n":
        server.kill()
        raise RuntimeError(f"server did not receive data after stdin EOF: {line!r}")
    sock.close()

    out, err = server.communicate(timeout=6)

    if server.returncode != 0:
        raise RuntimeError(f"server exited nonzero {server.returncode}, stderr={err}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("nc_path")
    args = parser.parse_args()
    run_quit_after_eof(args.nc_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
