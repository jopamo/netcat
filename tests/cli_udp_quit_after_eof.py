#!/usr/bin/env python3
import argparse
import socket
import subprocess
import sys
import time
import select


def free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_quit_after_eof_udp(nc_path: str) -> None:
    port = free_udp_port()
    server = subprocess.Popen(
        [nc_path, "-u", "-v", "-l", "-p", str(port), "-q", "2"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    time.sleep(0.2)  # allow bind

    # Start timer by closing stdin immediately.
    server.stdin.close()

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.sendto(b"hi\n", ("127.0.0.1", port))
    client.close()

    start = time.monotonic()
    ready, _, _ = select.select([server.stdout], [], [], 5)
    if not ready:
        server.kill()
        raise RuntimeError("UDP server did not output data in time")
    data = server.stdout.readline()
    if data != "hi\n":
        server.kill()
        raise RuntimeError(f"UDP server output mismatch: {data!r}")

    out, err = server.communicate(timeout=6)
    elapsed = time.monotonic() - start
    if server.returncode != 0:
        raise RuntimeError(f"server exited nonzero {server.returncode}, stderr={err}")
    if elapsed < 0.5 or elapsed > 5.0:
        raise RuntimeError(f"quit-after-eof duration out of range: {elapsed:.2f}s")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("nc_path")
    args = parser.parse_args()
    run_quit_after_eof_udp(args.nc_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
