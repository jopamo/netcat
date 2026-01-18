#!/usr/bin/env python3
import subprocess
import sys
import argparse

def run_test(nc_path, args, expected_exit, expected_stderr_part=None):
    cmd = [nc_path] + args
    result = subprocess.run(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    
    if result.returncode != expected_exit:
        print(f"FAILED: {' '.join(cmd)}")
        print(f"  Expected exit code {expected_exit}, got {result.returncode}")
        print(f"  Stderr: {result.stderr.strip()}")
        return False
    
    if expected_stderr_part and expected_stderr_part not in result.stderr:
        print(f"FAILED: {' '.join(cmd)}")
        print(f"  Expected stderr to contain: '{expected_stderr_part}'")
        print(f"  Actual stderr: {result.stderr.strip()}")
        return False
    
    print(f"PASSED: {' '.join(cmd)}")
    return True

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("nc_path")
    args = parser.parse_args()
    nc_path = args.nc_path

    tests = [
        # No args
        ([], 1, "usage:"),
        
        # Missing port in connect mode
        (["127.0.0.1"], 1, None), # Might print usage or error
        
        # Invalid port range (too large)
        (["127.0.0.1", "70000"], 1, "port number"),
        
        # Invalid port (garbage)
        (["127.0.0.1", "abc"], 1, "service \"abc\" unknown"), # Assuming 'abc' is not a service
        
        # Missing listen port (if -l requires port)
        # In BSD netcat, nc -l port is required. Or nc -l -p port.
        # nc -l without port might be invalid or imply random?
        # OpenBSD nc: nc -l 1234
        (["-l"], 1, None),
        
        # Invalid listen port
        (["-l", "80000"], 1, "port number"),
    ]

    all_passed = True
    for cmd_args, expected_exit, expected_err in tests:
        if not run_test(nc_path, cmd_args, expected_exit, expected_err):
            all_passed = False

    if not all_passed:
        sys.exit(1)
    
    print("\nAll CLI argument tests passed!")

if __name__ == "__main__":
    main()
