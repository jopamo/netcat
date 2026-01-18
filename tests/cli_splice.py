#!/usr/bin/env python3
import argparse
import socket
import subprocess
import sys
import time

def run_splice_test(nc_path: str) -> None:
    # Server: -l -v --splice 127.0.0.1 0
    # We want to check if data flows through splice
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        
        client_cmd = [nc_path, "--splice", "127.0.0.1", str(port)]
        client = subprocess.Popen(client_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        try:
            conn, addr = s.accept()
            test_data = "splice test data\n"
            client.stdin.write(test_data)
            client.stdin.flush()
            
            conn.settimeout(2.0)
            received = conn.recv(1024).decode()
            if received == test_data:
                print("Splice data transfer client -> server successful")
            else:
                raise RuntimeError(f"Splice data mismatch. Received: {received!r}")
            
            conn.sendall(b"response from server\n")
            client_received = client.stdout.readline()
            if client_received == "response from server\n":
                print("Splice data transfer server -> client successful")
            else:
                raise RuntimeError(f"Splice client response mismatch: {client_received!r}")
                
        finally:
            client.stdin.close()
            client.kill()
            client.communicate()

    print("Splice test passed!")

if __name__ == "__main__":
    run_splice_test(sys.argv[1])
