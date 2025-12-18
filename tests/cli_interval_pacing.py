#!/usr/bin/env python3
import argparse
import subprocess
import sys
import time
import socket


def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_interval_test(nc_path: str) -> None:
    port = free_tcp_port()
    server = subprocess.Popen(
        [nc_path, "-v", "-l", "-p", str(port), "-q", "1"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    client = subprocess.Popen(
        [nc_path, "127.0.0.1", str(port), "-i", "1", "-q", "1"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert client.stdin is not None
    client.stdin.write("line1\nline2\n")
    client.stdin.flush()
    client.stdin.close()

    timestamps = []
    start = time.monotonic()
    collected = ""
    while len(timestamps) < 2 and time.monotonic() - start < 5:
        chunk = server.stdout.read(6)
        if not chunk:
            break
        collected += chunk
        while "\n" in collected and len(timestamps) < 2:
            before, collected = collected.split("\n", 1)
            timestamps.append(time.monotonic())
    server.stdin.close()

    out_client, err_client = client.communicate(timeout=5)
    out_server, err_server = server.communicate(timeout=5)

    if client.returncode != 0 or server.returncode != 0:
        raise RuntimeError(
            f"nc exited nonzero: client={client.returncode}, server={server.returncode}\n"
            f"client stderr: {err_client}\nserver stderr: {err_server}"
        )

    if len(timestamps) != 2:
        raise RuntimeError("did not receive expected two lines")
    gap = timestamps[1] - timestamps[0]
    if gap < 0.8 or gap > 2.5:
        raise RuntimeError(f"interval gap out of range: {gap:.2f}s")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("nc_path")
    args = parser.parse_args()
    run_interval_test(args.nc_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
