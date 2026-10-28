"""Pins the Dockerfile to a Corvus release: its version and the SHA-256 SHA256SUMS lists for the linux-x64 archive.

Usage: python3 pin_corvus.py --version 2.8.0 --sums SHA256SUMS [--dockerfile Dockerfile]
"""

import argparse
import os
import re
import sys

# python -I leaves the script's own folder off sys.path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from install_corvus import ASSET, expected_sha256  # noqa: E402

PINS = (("CORVUS_VERSION", r"\d+\.\d+\.\d+"), ("CORVUS_SHA256", r"[0-9a-f]{64}"))


def pin(dockerfile: str, version: str, sha256: str) -> str:
    """Returns dockerfile with both ARG pins set; raises ValueError on a bad version or hash, or when an ARG is not
    found exactly once."""
    values = {"CORVUS_VERSION": version, "CORVUS_SHA256": sha256.lower()}
    for name, pattern in PINS:
        if not re.fullmatch(pattern, values[name]):
            raise ValueError(f"{name} {values[name]!r} does not match {pattern}")
        dockerfile, count = re.subn(rf"^ARG {name}=\S+$", f"ARG {name}={values[name]}", dockerfile, flags=re.M)
        if count != 1:
            raise ValueError(f"the Dockerfile has {count} ARG {name} lines, not 1")
    return dockerfile


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--sums", required=True)
    parser.add_argument("--dockerfile", default="Dockerfile")
    args = parser.parse_args(argv)
    with open(args.sums, encoding="utf-8") as f:
        sha256 = expected_sha256(f.read(), ASSET)
    with open(args.dockerfile, encoding="utf-8", newline="") as f:
        text = f.read()
    with open(args.dockerfile, "w", encoding="utf-8", newline="") as f:
        f.write(pin(text, args.version.lstrip("v"), sha256))
    print(f"Corvus {args.version.lstrip('v')} pinned: {sha256}  {ASSET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
