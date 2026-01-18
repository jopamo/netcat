#!/usr/bin/env python3
import socket
import subprocess
import sys
import os

def check_mptcp():
    if not os.path.exists("/proc/sys/net/mptcp/enabled"):
        return False
    with open("/proc/sys/net/mptcp/enabled", "r") as f:
        return f.read().strip() != "0"

def check_tfo():
    if not os.path.exists("/proc/sys/net/ipv4/tcp_fastopen"):
        return False
    with open("/proc/sys/net/ipv4/tcp_fastopen", "r") as f:
        return int(f.read().strip()) & 1 != 0 # 1 is client, 2 is server

def run_performance_test(nc_path: str) -> None:
    has_mptcp = check_mptcp()
    has_tfo = check_tfo()
    
    print(f"Kernel MPTCP support: {has_mptcp}")
    print(f"Kernel TFO support: {has_tfo}")

    # Test MPTCP if supported
    if has_mptcp:
        print("Testing MPTCP...")
        # Server
        server = subprocess.Popen([nc_path, "-l", "--mptcp", "127.0.0.1", "0"], stderr=subprocess.PIPE, text=True)
        # Port detection would be nice, but let's just see if it starts without error
        time.sleep(0.5)
        if server.poll() is not None:
            out, err = server.communicate()
            print(f"MPTCP server failed to start: {err}")
        else:
            print("MPTCP server started successfully")
            server.kill()

    # Test TFO if supported
    if has_tfo:
        print("Testing TFO...")
        server = subprocess.Popen([nc_path, "-l", "--tfo", "127.0.0.1", "0"], stderr=subprocess.PIPE, text=True)
        time.sleep(0.5)
        if server.poll() is not None:
            out, err = server.communicate()
            print(f"TFO server failed to start: {err}")
        else:
            print("TFO server started successfully")
            server.kill()

    # Test Mark (might fail if not root, so we check if it handles it)
    print("Testing Socket Mark...")
    server = subprocess.Popen([nc_path, "-l", "--mark", "123", "127.0.0.1", "0"], stderr=subprocess.PIPE, text=True)
    time.sleep(0.5)
    if server.poll() is not None:
        out, err = server.communicate()
        if "Operation not permitted" in err:
            print("Socket mark failed as expected (needs root/CAP_NET_ADMIN)")
        else:
            print(f"Socket mark server failed with unexpected error: {err}")
    else:
        print("Socket mark server started successfully (likely had permissions or kernel ignored it)")
        server.kill()

if __name__ == "__main__":
    import time
    run_performance_test(sys.argv[1])
