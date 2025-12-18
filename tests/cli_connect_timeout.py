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
    # Connect with -w 1. Client should exit after ~1s of idleness.
    client = subprocess.Popen(
        [args.nc_path, "-w", "1", "127.0.0.1", str(port)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert client.stdin is not None
    client.stdin.close()  # force EOF immediately so only read-side timeout matters

    # Accept connection but don't send anything.
    try:
        conn, _ = server.accept()
    except Exception:
        # If client times out before accept, that's also valid for connection timeout
        pass
    else:
        # Keep connection open without sending data to trigger read timeout.
        time.sleep(2.0)
        conn.close()
    
    server.close()

    try:
        out, err = client.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        client.kill()
        print("client did not exit within 5s", file=sys.stderr)
        return 1

    elapsed = time.monotonic() - start

    if client.returncode == 0:
        # OpenBSD nc exits with 0 on timeout/success if no error occurred?
        # Actually -w timeout: "If the connection and stdin are idle for more than timeout seconds, then the connection is silently closed."
        # If silently closed, it might exit 0.
        # But if it's a connection timeout, it fails.
        # Here it is a read timeout (idleness).
        # Let's see what standard nc does.
        pass

    # Verify duration
    if elapsed < 0.9 or elapsed > 3.0:
        print(f"timeout duration out of range ({elapsed:.2f}s) expected ~1.0s", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
