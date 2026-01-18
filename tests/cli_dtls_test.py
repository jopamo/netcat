#!/usr/bin/env python3
import argparse
import select
import socket
import subprocess
import sys
import time
import os

def free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def wait_for_listening_openssl(proc: subprocess.Popen, timeout: float) -> None:
    # Openssl s_server prints "ACCEPT" or similar when ready, but -quiet might suppress it.
    # Without -quiet, it's verbose.
    # Let's verify port binding by trying to peek?
    # Or just wait a bit.
    time.sleep(1)

def run_dtls_test(nc_path: str) -> None:
    port = free_udp_port()
    cert_path = os.path.abspath("cert.pem")
    key_path = os.path.abspath("key.pem")

    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        # Generate self-signed cert
        subprocess.check_call([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", cert_path,
            "-days", "1", "-nodes",
            "-subj", "/C=US/ST=Test/L=Test/O=Test/CN=localhost"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Start OpenSSL DTLS server
    server_cmd = [
        "openssl", "s_server",
        "-dtls",
        "-accept", str(port),
        "-cert", cert_path,
        "-key", key_path,
        "-quiet",
    ]
    
    server = subprocess.Popen(
        server_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        wait_for_listening_openssl(server, 2.0)
        
        # Client: nc --dtls -T noverify -v -R cert.pem 127.0.0.1 <port>
        client_cmd = [nc_path, "--dtls", "-T", "noverify", "-v", "-R", cert_path, "127.0.0.1", str(port)]
        
        client = subprocess.Popen(
            client_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        assert client.stdin is not None
        assert server.stdin is not None

        # Write to client
        msg = "hello dtls\n"
        client.stdin.write(msg)
        client.stdin.flush()
        
        # OpenSSL s_server should receive this.
        # Since we didn't use -quiet on s_server (oh we did), it prints payload to stdout?
        # With -quiet, s_server implies "Session cache: ...".
        # Let's remove -quiet to see output, but valid logic is:
        # s_server prints received data to stdout.
        
        # Wait for data on server stdout
        collected = ""
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if select.select([server.stdout], [], [], 0.1)[0]:
                data = server.stdout.readline()
                if data:
                    collected += data
                    if msg.strip() in collected:
                        break
        
        if msg.strip() not in collected:
            # Maybe it hasn't flushed?
            pass

    finally:
        client.terminate()
        server.terminate()
        try:
            out_c, err_c = client.communicate(timeout=1)
        except:
            out_c, err_c = "", ""
        try:
            out_s, err_s = server.communicate(timeout=1)
        except:
            out_s, err_s = "", ""
            
    if msg.strip() not in collected:
         raise RuntimeError(f"Server did not receive message. Got: {collected!r}\nClient Stderr: {err_c}\nServer Stderr: {err_s}\nServer Stdout: {out_s}")

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("nc_path")
    args = parser.parse_args()
    run_dtls_test(args.nc_path)
    return 0

if __name__ == "__main__":
    sys.exit(main())
