import socket
import subprocess
import time
import select
import os
import signal
import threading
from typing import Tuple, List, Optional

class NetcatPeer:
    def __init__(self, nc_path: str, args: List[str]):
        self.nc_path = nc_path
        self.args = args
        self.proc: Optional[subprocess.Popen] = None
        self.stdout = ""
        self.stderr = ""

    def start(self):
        self.proc = subprocess.Popen(
            [self.nc_path] + self.args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

    def wait_for_stderr(self, patterns: List[str], timeout: float = 5.0):
        if not self.proc:
            raise RuntimeError("Process not started")
        
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0: break
            
            rlist, _, _ = select.select([self.proc.stderr], [], [], remaining)
            if not rlist:
                continue
            
            line = self.proc.stderr.readline()
            if not line:
                break
            self.stderr += line
            for pattern in patterns:
                if pattern.lower() in line.lower():
                    return
        
        raise TimeoutError(f"None of patterns {patterns} found in stderr after {timeout}s. Stderr so far:\n{self.stderr}")

    def send(self, data: str):
        if not self.proc or not self.proc.stdin:
            raise RuntimeError("Process not started or stdin unavailable")
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def close_stdin(self):
        if self.proc and self.proc.stdin:
            self.proc.stdin.close()

    def communicate(self, timeout: float = 5.0) -> Tuple[str, str]:
        if not self.proc:
            raise RuntimeError("Process not started")
        out, err = self.proc.communicate(timeout=timeout)
        self.stdout += out
        self.stderr += err
        return self.stdout, self.stderr

    def stop(self):
        if self.proc:
            if self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    self.proc.kill()

def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def tcp_pair(nc_path: str, server_args: List[str] = [], client_args: List[str] = []) -> Tuple[NetcatPeer, NetcatPeer]:
    port = free_tcp_port()
    
    server = NetcatPeer(nc_path, ["-v", "-l", "127.0.0.1", str(port)] + server_args)
    server.start()
    server.wait_for_stderr(["listening on", "bound"])
    
    client = NetcatPeer(nc_path, ["127.0.0.1", str(port)] + client_args)
    client.start()
    
    return server, client

def unix_pair(nc_path: str, server_args: List[str] = [], client_args: List[str] = []) -> Tuple[NetcatPeer, NetcatPeer, str]:
    path = f"/tmp/nc_test_socket_{{os.getpid()}}_{{time.time_ns()}}"
    if os.path.exists(path):
        os.unlink(path)
    
    server = NetcatPeer(nc_path, ["-v", "-l", "-U", path] + server_args)
    server.start()
    server.wait_for_stderr(["listening on", "bound"])
    
    client = NetcatPeer(nc_path, ["-U", path] + client_args)
    client.start()
    
    return server, client, path