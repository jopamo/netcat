#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
import time

def run_json_test(nc_path: str) -> None:
    # Test listener JSON output
    # Server: -l -v -j 127.0.0.1 0
    server_cmd = [nc_path, "-v", "-j", "-l", "127.0.0.1", "0"]
    
    server = subprocess.Popen(
        server_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    # Wait for listener to bind and output JSON
    deadline = time.monotonic() + 3.0
    bound_json = None
    while time.monotonic() < deadline:
        line = server.stderr.readline()
        if not line:
            if server.poll() is not None:
                break
            continue
        try:
            data = json.loads(line)
            if data.get("event") == "Listening":
                bound_json = data
                break
        except json.JSONDecodeError:
            continue
    
    if not bound_json:
        server.kill()
        out, err = server.communicate()
        raise RuntimeError(f"Did not receive JSON Listening event. stderr: {err}")

    port = bound_json.get("port")
    if not port:
        server.kill()
        raise RuntimeError(f"JSON Listening event missing port: {bound_json}")

    # Client: 127.0.0.1 [port] -v -j
    client_cmd = [nc_path, "-v", "-j", "127.0.0.1", str(port)]
    client = subprocess.Popen(
        client_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    # Wait for client to connect and output JSON
    deadline = time.monotonic() + 3.0
    client_json = None
    while time.monotonic() < deadline:
        line = client.stderr.readline()
        if not line:
            if client.poll() is not None:
                break
            continue
        try:
            data = json.loads(line)
            if data.get("event") == "connection_succeeded":
                client_json = data
                break
        except json.JSONDecodeError:
            continue

    if not client_json:
        client.kill()
        server.kill()
        out, err = client.communicate()
        raise RuntimeError(f"Did not receive JSON connection_succeeded event. stderr: {err}")

    # Clean up
    client.stdin.close()
    server.stdin.close()
    client.kill()
    server.kill()
    
    print("JSON output test passed!")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("nc_path")
    args = parser.parse_args()
    try:
        run_json_test(args.nc_path)
    except Exception as e:
        print(f"Test failed: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
