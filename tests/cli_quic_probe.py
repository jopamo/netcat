#!/usr/bin/env python3
import argparse
import select
import socket
import subprocess
import sys
import time
import os
import struct

def free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def run_quic_server(port, stop_event):
    """
    A simple UDP server that listens for QUIC Long Header packets with unknown versions
    and replies with a Version Negotiation packet.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", port))
        s.settimeout(1.0)
        
        # print(f"QUIC Mock Server listening on {port}", file=sys.stderr)
        
        while not stop_event.is_set():
            try:
                data, addr = s.recvfrom(2048)
                # print(f"Received {len(data)} bytes from {addr}", file=sys.stderr)
                
                if len(data) > 0:
                    first_byte = data[0]
                    # Check for Long Header (0x80)
                    if (first_byte & 0x80):
                        # Version is at offset 1
                        if len(data) >= 5:
                            version = struct.unpack("!I", data[1:5])[0]
                            # print(f"Version: {version:08x}", file=sys.stderr)
                            
                            # If version is our "grease" version 0xbadc0de1, send Version Negotiation
                            if version == 0xbadc0de1:
                                # Construct Version Negotiation Packet
                                # Header: 1xxxxxxx | Version=0
                                reply = bytearray()
                                reply.append(0x80 | 0x40) # Form=1, Fixed=1? Or just random?
                                # RFC 9000: Version Negotiation Packet
                                # Form=1, Unused=Random?
                                # Version = 0
                                reply.extend(struct.pack("!I", 0))
                                
                                # DCID from client becomes SCID
                                # SCID from client becomes DCID
                                # We need to parse DCID len from client packet.
                                # Client packet: Form|Fixed|Type|TypeSpec
                                # Version (4)
                                # DCID Len (1)
                                # DCID (N)
                                dcid_len = data[5]
                                dcid = data[6:6+dcid_len]
                                
                                # SCID Len (1) - Client sent 0
                                scid_len_offset = 6 + dcid_len
                                # scid_len = data[scid_len_offset]
                                
                                # Reply:
                                # DCID (from Client SCID) -> Client sent empty SCID.
                                # Wait, Version Negotiation format:
                                # 1 | Unused (7)
                                # Version (0)
                                # DCID Len (1)
                                # DCID (Variable) -> From Client SCID
                                # SCID Len (1)
                                # SCID (Variable) -> From Client DCID
                                # Supported Versions (Variable)
                                
                                # Client sent:
                                # DCID = Random 8 bytes.
                                # SCID = Empty.
                                
                                # Server Reply:
                                # DCID = Client SCID (Empty)
                                # SCID = Client DCID (Random 8 bytes)
                                
                                reply.append(0) # DCID Len = 0
                                # No DCID bytes
                                
                                reply.append(dcid_len) # SCID Len = 8
                                reply.extend(dcid)     # SCID bytes
                                
                                # Supported Versions: 1 (0x00000001)
                                reply.extend(struct.pack("!I", 1))
                                
                                s.sendto(reply, addr)
                                # print("Sent Version Negotiation", file=sys.stderr)

            except socket.timeout:
                continue
            except Exception as e:
                print(f"Server error: {e}", file=sys.stderr)

import threading

def run_quic_test(nc_path: str) -> None:
    port = free_udp_port()
    stop_event = threading.Event()
    server_thread = threading.Thread(target=run_quic_server, args=(port, stop_event))
    server_thread.start()
    
    try:
        time.sleep(1) # Wait for server
        
        # Run nc --quic
        cmd = [nc_path, "--quic", "-v", "127.0.0.1", str(port)]
        
        # print(f"Running: {' '.join(cmd)}", file=sys.stderr)
        
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5
        )
        
        if res.returncode != 0:
            raise RuntimeError(f"nc failed: {res.stderr}")
            
        if "QUIC Connection to 127.0.0.1" not in res.stderr and "QUIC Version Negotiation packet received" not in res.stderr:
             # Depending on verbosity, we look for success message
             # With -v, we expect "QUIC Connection ... succeeded!"
             if "succeeded!" not in res.stderr:
                 raise RuntimeError(f"nc did not report success. Stderr: {res.stderr}")

    finally:
        stop_event.set()
        server_thread.join()

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("nc_path")
    args = parser.parse_args()
    run_quic_test(args.nc_path)
    return 0

if __name__ == "__main__":
    sys.exit(main())
