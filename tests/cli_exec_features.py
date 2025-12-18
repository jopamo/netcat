#!/usr/bin/env python3
import argparse
import os
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
from typing import Iterable, Optional


def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_listening(proc: subprocess.Popen, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    collected = ""
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"nc exited early: {proc.returncode}, stderr: {proc.stderr.read()}")
        remaining = deadline - time.monotonic()
        rlist, _, _ = select.select([proc.stderr], [], [], remaining)
        if not rlist:
            continue
        line = proc.stderr.readline()
        collected += line
        if "listening on" in line:
            return
    raise RuntimeError(f"listener did not become ready; stderr so far:\n{collected}")


def recv_all(sock: socket.socket, timeout: float = 3.0) -> str:
    sock.settimeout(timeout)
    chunks = []
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks).decode()


def cleanup_process(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.kill()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)


def start_server(
    nc_path: str,
    port: int,
    extra_args: Iterable[str],
    env: Optional[dict] = None,
    pass_fds: Optional[Iterable[int]] = None,
    preexec_fn=None,
) -> subprocess.Popen:
    cmd = [nc_path, "-v", "-l", "-p", str(port)]
    cmd.extend(extra_args)
    env_map = os.environ.copy()
    if env:
        env_map.update(env)

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env_map,
        pass_fds=list(pass_fds) if pass_fds else (),
        preexec_fn=preexec_fn,
    )
    wait_for_listening(proc, timeout=5.0)
    return proc


def case_exec_argv(nc_path: str, helper_path: str) -> None:
    port = free_tcp_port()
    server = start_server(nc_path, port, ["--exec-argv", helper_path, "arg-one", "arg-two"])
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
            data = recv_all(sock)
        rc = server.wait(timeout=3)
        if rc != 0:
            raise RuntimeError(f"nc exited nonzero ({rc}), stderr: {server.stderr.read()}")
        expected = f"argv:{helper_path} arg-one arg-two"
        if expected not in data:
            raise RuntimeError(f"exec argv missing in output: {data!r}")
    finally:
        cleanup_process(server)


def case_exec_close_fds(nc_path: str, helper_path: str, inherit: bool) -> None:
    port = free_tcp_port()
    with tempfile.TemporaryFile() as tmp:
        fd = tmp.fileno()
        env = {"CHECK_FD": str(fd)}
        args = ["--exec-argv", helper_path]
        if inherit:
            args.insert(0, "--exec-inherit-fds")
        server = start_server(nc_path, port, args, env=env, pass_fds=[fd])
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
                data = recv_all(sock)
            rc = server.wait(timeout=3)
            if rc != 0:
                raise RuntimeError(f"nc exited nonzero ({rc}), stderr: {server.stderr.read()}")
        finally:
            cleanup_process(server)

    marker = "open" if inherit else "closed"
    needle = f"fd:{fd}:{marker}"
    if needle not in data:
        raise RuntimeError(f"expected {needle!r} in output, got {data!r}")


def ignore_and_block_sigusr1() -> None:
    signal.signal(signal.SIGUSR1, signal.SIG_IGN)
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1})
    except AttributeError:
        pass


def case_exec_reset_signals(nc_path: str, helper_path: str) -> None:
    port = free_tcp_port()
    env = {"REPORT_SIGUSR1": "1"}
    server = start_server(
        nc_path,
        port,
        ["--exec-reset-signals", "--exec-argv", helper_path, "stay"],
        env=env,
        preexec_fn=ignore_and_block_sigusr1,
    )
    output = ""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
            sock.settimeout(3)
            start = time.monotonic()
            while "ready\n" not in output and time.monotonic() - start < 3:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                output += chunk.decode()
            if "ready\n" not in output:
                raise RuntimeError(f"did not see readiness marker, output: {output!r}")

        server.send_signal(signal.SIGUSR1)
        rc = server.wait(timeout=3)
        if rc != -signal.SIGUSR1:
            raise RuntimeError(f"expected termination by SIGUSR1, rc={rc}, stderr: {server.stderr.read()}")
    finally:
        cleanup_process(server)

    if "sigusr1:DFL:unblocked" not in output:
        raise RuntimeError(f"signal state not reset: {output!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("nc_path")
    parser.add_argument("helper_path")
    parser.add_argument("--case", required=True, choices=["exec-argv", "close-fds", "inherit-fds", "reset-signals"])
    args = parser.parse_args()

    cases = {
        "exec-argv": case_exec_argv,
        "close-fds": lambda nc, helper: case_exec_close_fds(nc, helper, inherit=False),
        "inherit-fds": lambda nc, helper: case_exec_close_fds(nc, helper, inherit=True),
        "reset-signals": case_exec_reset_signals,
    }

    cases[args.case](args.nc_path, args.helper_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
