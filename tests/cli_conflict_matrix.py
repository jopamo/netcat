#!/usr/bin/env python3
import subprocess
import sys
import argparse

def run_conflict_test(nc_path, args, expected_error):
    cmd = [nc_path] + args
    result = subprocess.run(cmd, stderr=subprocess.PIPE, text=True)
    
    if result.returncode != 1:
        print(f"FAILED: {' '.join(cmd)}")
        print(f"  Expected exit code 1, got {result.returncode}")
        return False
    
    if expected_error not in result.stderr:
        print(f"FAILED: {' '.join(cmd)}")
        print(f"  Expected error containing: '{expected_error}'")
        print(f"  Actual stderr: {result.stderr.strip()}")
        return False
    
    print(f"PASSED: {' '.join(cmd)}")
    return True

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("nc_path")
    args = parser.parse_args()
    nc_path = args.nc_path

    conflicts = [
        (["-l", "-s", "127.0.0.1", "1234"], "cannot use -s and -l"),
        (["-l", "-p", "1234", "localhost", "1234"], "cannot use -p and -l"),
        (["-l", "-z", "localhost", "1234"], "cannot use -z and -l"),
        (["--keep-open", "localhost", "1234"], "must use -l with --keep-open"),
        (["-u", "-c", "localhost", "1234"], "cannot use -c and -u"),
        (["--splice", "-c", "localhost", "1234"], "cannot use --splice with TLS, UDP, port scanning or FD passing"),
        (["--splice", "-u", "localhost", "1234"], "cannot use --splice with TLS, UDP, port scanning or FD passing"),
        (["--splice", "-z", "localhost", "1234"], "cannot use --splice with TLS, UDP, port scanning or FD passing"),
        (["--splice", "-F", "localhost", "1234"], "cannot use --splice with TLS, UDP, port scanning or FD passing"),
        (["-U", "-c", "/tmp/sock"], "cannot use -c and -U"),
        (["-U", "-F", "/tmp/sock"], "cannot use -F and -U"),
        (["-c", "-F", "localhost", "1234"], "cannot use -c and -F"),
        (["-C", "cert.pem", "localhost", "1234"], "you must specify -c to use -C"),
        (["-K", "key.pem", "localhost", "1234"], "you must specify -c to use -K"),
        (["-Z", "out.pem", "localhost", "1234"], "you must specify -c to use -Z"),
        (["-R", "ca.pem", "localhost", "1234"], "you must specify -c to use -R"),
        (["-H", "hash", "localhost", "1234"], "you must specify -c to use -H"),
        (["-x", "localhost:8080", "-u", "localhost", "1234"], "no proxy support for UDP mode"),
        (["-x", "localhost:8080", "-l", "1234"], "no proxy support for listen"),
        (["-x", "localhost:8080", "-U", "/tmp/sock"], "no proxy support for unix sockets"),
        (["-x", "localhost:8080", "-s", "127.0.0.1", "localhost", "1234"], "no proxy support for local source address"),
    ]

    all_passed = True
    for cmd_args, expected_error in conflicts:
        if not run_conflict_test(nc_path, cmd_args, expected_error):
            all_passed = False

    if not all_passed:
        sys.exit(1)
    
    print("\nAll CLI conflict matrix tests passed!")

if __name__ == "__main__":
    main()
