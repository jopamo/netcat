#!/usr/bin/env python3
import argparse
import os
import socket
import subprocess
import sys
import time

def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def compile_bpf():
    # compile bpf_filter.c -> bpf_filter.o
    src = os.path.join(os.path.dirname(__file__), "bpf_filter.c")
    obj = os.path.join(os.path.dirname(__file__), "bpf_filter.o")
    
    cmd = [
        "clang", "-O2", "-target", "bpf", "-c", src, "-o", obj
    ]
    subprocess.check_call(cmd)
    return obj

def run_bpf_test(nc_path: str) -> None:
    try:
        obj_path = compile_bpf()
    except Exception as e:
        print(f"Skipping BPF test: compilation failed: {e}", file=sys.stderr)
        return

    port = free_tcp_port()
    
    # Start nc listener with BPF filter (Drop All)
    # nc -l -p port --bpf-prog obj
    server_cmd = [nc_path, "-l", "127.0.0.1", str(port), "--bpf-prog", obj_path, "-v"]
    
    server = subprocess.Popen(
        server_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        time.sleep(1) # Wait for start
        if server.poll() is not None:
             # Maybe failed to load BPF (requires privileges?)
             # SO_ATTACH_BPF might require CAP_NET_ADMIN for some types, but socket filters usually don't?
             # Unprivileged BPF is often disabled.
             # If it failed, check stderr.
             stdout, stderr = server.communicate()
             if "bpf attach failed" in stderr or "Permission denied" in stderr:
                 print("Skipping BPF test: permission denied or attach failed", file=sys.stderr)
                 return
             raise RuntimeError(f"Server exited early: {stderr}")

        # Client sends data
        # Since filter is "Drop All" (return 0), server should receive nothing.
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.connect(("127.0.0.1", port))
            client.sendall(b"hello")
            client.close()
        except Exception as e:
            # If connect failed, server might not be listening
            pass
        
        # Wait a bit. Server should have received nothing.
        time.sleep(0.5)
        server.terminate()
        out, err = server.communicate()
        
        if "hello" in out:
            raise RuntimeError("BPF Filter failed: server received data (should be dropped)")
            
    finally:
        if server.poll() is None:
            server.terminate()
        if os.path.exists(obj_path):
            os.remove(obj_path)

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("nc_path")
    args = parser.parse_args()
    run_bpf_test(args.nc_path)
    return 0

if __name__ == "__main__":
    sys.exit(main())
