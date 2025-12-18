#!/usr/bin/env python3
import argparse
import socket
import subprocess
import sys
import time


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("nc_path")
    args = parser.parse_args()

    # Create a local TCP listener that accepts and then stalls without sending data.
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    start = time.monotonic()
    client = subprocess.Popen(
        [args.nc_path, "-w", "1", "127.0.0.1", str(port)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert client.stdin is not None
    client.stdin.close()  # force EOF immediately so only read-side timeout matters

    conn, _ = server.accept()
    # Keep connection open without sending data to trigger read timeout.
    time.sleep(2.0)
    conn.close()
    server.close()

    out, err = client.communicate(timeout=5)
    elapsed = time.monotonic() - start

    if client.returncode == 0:
        print("client exited success despite timeout expectation", file=sys.stderr)
        return 1
    if elapsed < 1.0 or elapsed > 4.0:
        print(f"timeout duration out of range ({elapsed:.2f}s)", file=sys.stderr)
        return 1
    # No specific message required; behavior is exit on timeout.
    return 0


if __name__ == "__main__":
    sys.exit(main())
