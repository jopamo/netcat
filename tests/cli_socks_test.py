#!/usr/bin/env python3
import socket
import threading
import subprocess
import sys
import time
import argparse

def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def socks5_proxy(proxy_port, target_port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('127.0.0.1', proxy_port))
            s.listen(1)
            print(f"Proxy listening on {proxy_port}")
            conn, addr = s.accept()
            print(f"Proxy accepted connection from {addr}")
            with conn:
                # Greeting
                data = conn.recv(1024)
                print(f"Proxy received greeting: {data}")
                if not data or data[0] != 5: return
                conn.sendall(b'\x05\x00')
                
                # Request
                data = conn.recv(1024)
                print(f"Proxy received request: {data}")
                if not data or data[0] != 5 or data[1] != 1: return
                
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as target:
                    target.connect(('127.0.0.1', target_port))
                    conn.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
                    
                    # Shovel
                    def shovel(src, dst):
                        try:
                            while True:
                                d = src.recv(4096)
                                if not d: break
                                dst.sendall(d)
                            dst.shutdown(socket.SHUT_WR)
                        except: pass
                    
                    t1 = threading.Thread(target=shovel, args=(conn, target))
                    t2 = threading.Thread(target=shovel, args=(target, conn))
                    t1.start(); t2.start()
                    t1.join(); t2.join()
    except Exception as e:
        print(f"Proxy error: {e}")

def run_test(nc_path, version, use_domain=False):
    proxy_port = free_tcp_port()
    target_port = free_tcp_port()
    
    # Start target server (using nc)
    target_cmd = [nc_path, '-l', '127.0.0.1', str(target_port)]
    target = subprocess.Popen(target_cmd, stdout=subprocess.PIPE, text=True)
    
    # Start proxy stub
    t = threading.Thread(target=socks5_proxy, args=(proxy_port, target_port))
    t.daemon = True
    t.start()
    
    time.sleep(0.5)
    
    # Start nc client
    host = '127.0.0.1' if not use_domain else 'localhost'
    client_cmd = [nc_path, '-N', '-v', '-x', f'127.0.0.1:{proxy_port}', '-X', str(version), host, str(target_port)]
    client = subprocess.Popen(client_cmd, stdin=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    client.stdin.write("hello from client\n")
    client.stdin.close()
    
    try:
        out, _ = target.communicate(timeout=3.0)
        # print(f"Target received: {out}")
        if "hello from client" not in out:
            _, err_client = client.communicate()
            raise RuntimeError(f"SOCKS{version} test failed: unexpected output '{out}'. Client stderr: {err_client}")
    except subprocess.TimeoutExpired:
        target.kill()
        _, err_client = client.communicate()
        raise RuntimeError(f"SOCKS{version} test failed: timeout. Client stderr: {err_client}")
    
    client.wait()
    print(f"SOCKS{version} {'(domain)' if use_domain else ''} test passed")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("nc_path")
    args = parser.parse_args()
    
    print("Running SOCKS5 tests...")
    run_test(args.nc_path, 5)
    run_test(args.nc_path, 5, use_domain=True)

if __name__ == "__main__":
    main()