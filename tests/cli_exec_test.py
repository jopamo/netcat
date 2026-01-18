#!/usr/bin/env python3
import socket
import subprocess
import time
import sys

def exec_supported(nc_path: str) -> bool:
    # Detect whether -e is enabled (GAPING_SECURITY_HOLE). If not, nc exits with a TLS error.
    probe_cmd = [nc_path, "-l", "127.0.0.1", "0", "-e", "/bin/cat"]
    proc = subprocess.Popen(probe_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(0.2)
    ret = proc.poll()
    if ret is not None:
        err = proc.stderr.read().decode()
        proc.wait()
        if "you must specify -c to use -e" in err:
            return False
        return True
    proc.terminate()
    try:
        proc.wait(timeout=1)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    return True

def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def run_exec_test(nc_path):
    port = free_tcp_port()
    
    # Start server with -e /bin/cat (echo server)
    server_cmd = [nc_path, "-v", "-l", "127.0.0.1", str(port), "-e", "/bin/cat"]
    server = subprocess.Popen(server_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    time.sleep(0.5)
    
    try:
        with socket.create_connection(("127.0.0.1", port)) as s:
            s.settimeout(5.0)
            s.sendall(b"Hello Exec\n")
            # Don't shutdown yet, wait for response
            data = s.recv(1024)
            
            if b"Hello Exec" in data:
                print("Exec test passed")
            else:
                print(f"Exec test failed: received {data}")
                _, err = server.communicate(timeout=1)
                print(f"Server stderr: {err.decode()}")
                sys.exit(1)
    except Exception as e:
        server.kill()
        out, err = server.communicate()
        print(f"Exec test failed with exception: {e}")
        print(f"Server stderr: {err.decode()}")
        sys.exit(1)
    server.terminate()
    server.wait()

def run_exec_args_test(nc_path):
    port = free_tcp_port()
    # /bin/sh -c "/bin/echo 'hello world'"
    server_cmd = [nc_path, "-l", "127.0.0.1", str(port), "-e", "/bin/echo 'hello world'"]
    server = subprocess.Popen(server_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    time.sleep(0.5)
    
    try:
        with socket.create_connection(("127.0.0.1", port)) as s:
            data = s.recv(1024)
            if b"hello world" in data:
                print("Exec args test passed")
            else:
                print(f"Exec args test failed: received {data}")
                sys.exit(1)
    except Exception as e:
        server.kill()
        print(f"Exec args test failed with exception: {e}")
        sys.exit(1)
    server.terminate()
    server.wait()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: cli_exec_test.py <nc_path>")
        sys.exit(1)
    if not exec_supported(sys.argv[1]):
        print("Exec feature not enabled; skipping cli_exec_test.")
        sys.exit(0)
    run_exec_test(sys.argv[1])
    run_exec_args_test(sys.argv[1])
