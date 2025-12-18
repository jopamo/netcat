#!/usr/bin/env python3
import argparse
import pathlib
import subprocess
import sys


EXPECTED = "Source routing options (-g/-G) have been removed"


def check_help(nc_path: str) -> list[str]:
    proc = subprocess.run(
        [nc_path, "-h"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    errors: list[str] = []
    combined = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        errors.append(f"nc -h exited with {proc.returncode}")
    if EXPECTED not in combined:
        errors.append("help output missing expected removal notice")
    return errors


def check_file(path: pathlib.Path) -> list[str]:
    if not path.exists():
        return [f"{path} missing"]
    content = path.read_text(encoding="utf-8", errors="ignore")
    if EXPECTED not in content:
        return [f"{path} missing expected removal notice"]
    return []


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("nc_path")
    args = parser.parse_args()

    root = pathlib.Path(__file__).resolve().parent.parent
    errors = []
    errors.extend(check_help(args.nc_path))
    for rel in ("README.md", "man/nc.1"):
        errors.extend(check_file(root / rel))

    if errors:
        for msg in errors:
            print(msg, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
