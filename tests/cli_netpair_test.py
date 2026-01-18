#!/usr/bin/env python3
import sys
import argparse
import os
from netpair import tcp_pair, unix_pair

def test_tcp(nc_path):
    print("Testing TCP pair...")
    server, client = tcp_pair(nc_path, server_args=["-N"], client_args=["-N"])
    try:
        client.send("ping\n")
        client.close_stdin()
        
        server.send("pong\n")
        server.close_stdin()
        
        out_c, err_c = client.communicate()
        out_s, err_s = server.communicate()
        
        if "pong\n" not in out_c:
            raise RuntimeError(f"Client did not receive pong: {out_c!r}")
        if "ping\n" not in out_s:
            raise RuntimeError(f"Server did not receive ping: {out_s!r}")
        
        print("TCP pair test passed")
    finally:
        server.stop()
        client.stop()

def test_unix(nc_path):
    print("Testing Unix pair...")
    server, client, path = unix_pair(nc_path, server_args=["-N"], client_args=["-N"])
    try:
        client.send("unix-ping\n")
        client.close_stdin()
        
        server.send("unix-pong\n")
        server.close_stdin()
        
        out_c, err_c = client.communicate()
        out_s, err_s = server.communicate()
        
        if "unix-pong\n" not in out_c:
            raise RuntimeError(f"Client did not receive pong: {out_c!r}")
        if "unix-ping\n" not in out_s:
            raise RuntimeError(f"Server did not receive ping: {out_s!r}")
        
        print("Unix pair test passed")
    finally:
        server.stop()
        client.stop()
        if os.path.exists(path):
            os.unlink(path)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("nc_path")
    args = parser.parse_args()
    
    test_tcp(args.nc_path)
    test_unix(args.nc_path)

if __name__ == "__main__":
    main()
