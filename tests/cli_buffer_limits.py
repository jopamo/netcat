#!/usr/bin/env python3
import socket
import subprocess
import time
import os
import sys
import hashlib

def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def run_buffer_test(nc_path):
    port = free_tcp_port()
    payload_size = 1 * 1024 * 1024 # 1 MB
    payload = os.urandom(payload_size)
    payload_hash = hashlib.sha256(payload).hexdigest()
    
    # Start server
    server_cmd = [nc_path, "-l", "127.0.0.1", str(port)]
    server = subprocess.Popen(server_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Start client (using python socket for control)
    time.sleep(0.5)
    try:
        with socket.create_connection(("127.0.0.1", port)) as s:
            # Send all data
            s.sendall(payload)
            s.shutdown(socket.SHUT_WR)
            
            # Read response if any (echo?) - netcat server echoes by default if we pipe to it?
            # Wait, netcat server reads from network and writes to stdout.
            # We are capturing stdout.
    except Exception as e:
        server.kill()
        raise e

    # Check server output
    out, err = server.communicate(timeout=10)
    received_hash = hashlib.sha256(out).hexdigest()
    
    if received_hash != payload_hash:
        print(f"Hash mismatch! Sent {payload_hash}, received {received_hash}")
        print(f"Received length: {len(out)}")
        sys.exit(1)
        
    print("Buffer limits test passed (10MB transfer)")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: cli_buffer_limits.py <nc_path>")
        sys.exit(1)
    run_buffer_test(sys.argv[1])
