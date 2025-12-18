#!/usr/bin/env python3
import argparse
import subprocess
import sys


CASES = {
    "ipv6_disabled": {
        "args": ["-6", "localhost", "80"],
        "message": "IPv6 support not compiled in",
    },
    "exec_disabled": {
        "args": ["-e", "/bin/true", "localhost", "80"],
        "message": "Exec feature (-e/-c) not enabled at compile time",
    },
}


def run_case(nc_path: str, case: str) -> int:
    if case not in CASES:
        print(f"Unknown case {case}", file=sys.stderr)
        return 1

    spec = CASES[case]
    proc = subprocess.run(
        [nc_path] + spec["args"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    combined = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode == 0:
        print(f"{case} expected failure but exited 0", file=sys.stderr)
        return 1
    if spec["message"] not in combined:
        print(f"{case} missing expected message: {spec['message']}", file=sys.stderr)
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("nc_path")
    parser.add_argument("--case", required=True, choices=CASES.keys())
    args = parser.parse_args()
    return run_case(args.nc_path, args.case)


if __name__ == "__main__":
    sys.exit(main())
