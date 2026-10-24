"""Downloads a Corvus release archive, checks its pinned SHA-256 and SHA256SUMS line, and unpacks it.

Usage: python3 install_corvus.py --version 2.5.1 --sha256 <hex> --dest /opt/corvus [--asset corvus-linux-x64.tar.gz]
"""

import argparse
import hashlib
import io
import os
import sys
import tarfile
import urllib.request

RELEASES = "https://github.com/Albasha0x0/Corvus/releases/download"
ASSET = "corvus-linux-x64.tar.gz"


def expected_sha256(sums: str, asset: str) -> str:
    """Returns the lower-case SHA-256 SHA256SUMS lists for asset; raises ValueError when it lists none."""
    for line in sums.splitlines():
        parts = line.strip().split()
        if len(parts) == 2 and parts[1].lstrip("*") == asset:
            return parts[0].lower()
    raise ValueError(f"SHA256SUMS lists no {asset}; refusing an unverified build")


def verify(data: bytes, pinned: str, sums: str, asset: str) -> None:
    """Raises ValueError unless data's SHA-256 equals the pinned value and the one SHA256SUMS lists for asset.

    The pin refuses a release replaced on the server; SHA256SUMS alone, fetched beside the archive, only catches
    corruption.
    """
    pinned, actual = pinned.lower(), hashlib.sha256(data).hexdigest()
    if actual != pinned:
        raise ValueError(f"checksum mismatch for {asset}: pinned {pinned}, got {actual}")
    listed = expected_sha256(sums, asset)
    if listed != pinned:
        raise ValueError(f"SHA256SUMS lists {listed} for {asset}, not the pinned {pinned}")


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=300) as response:
        return response.read()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--dest", required=True)
    parser.add_argument("--asset", default=ASSET)
    args = parser.parse_args(argv)

    base = f"{RELEASES}/v{args.version}"
    data = fetch(f"{base}/{args.asset}")
    verify(data, args.sha256, fetch(f"{base}/SHA256SUMS").decode("utf-8"), args.asset)
    os.makedirs(args.dest, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        archive.extractall(args.dest, filter="data")
    os.chmod(os.path.join(args.dest, "corvus"), 0o755)
    print(f"Corvus {args.version}: {args.asset} matched the pinned SHA-256 and SHA256SUMS, unpacked to {args.dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
