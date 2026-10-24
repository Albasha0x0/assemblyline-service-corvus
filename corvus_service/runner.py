"""The corvus batch command line and the time limits it runs under."""

import hashlib
import os
from typing import List, Optional

CORVUS = "/opt/corvus/corvus"

# Exit codes of corvus batch that still write a document.
EXIT_OK = 0
EXIT_TIMEOUT = 124

# Seconds left to the service after Corvus stops: result upload and file attachment.
RESERVE_SECONDS = 30
# Seconds Corvus gets past its own time limit to write the document before it is killed.
GRACE_SECONDS = 15
MIN_TIME_LIMIT = 10
# Seconds before the service timeout by which Corvus is always stopped.
STOP_MARGIN_SECONDS = 5


def time_limit(service_timeout: int) -> int:
    """Returns the Corvus time limit in seconds for a service timeout: the timeout less the reserve and grace,
    at least half the timeout and at least MIN_TIME_LIMIT."""
    return max(MIN_TIME_LIMIT, service_timeout // 2, service_timeout - RESERVE_SECONDS - GRACE_SECONDS)


def kill_after(limit: int, service_timeout: int) -> int:
    """Returns the seconds after which a corvus process that has not exited is killed: the limit plus the grace,
    at most the service timeout less STOP_MARGIN_SECONDS, and at least 1."""
    return max(1, min(limit + GRACE_SECONDS, service_timeout - STOP_MARGIN_SECONDS))


def rules_digest(rules: Optional[str]) -> Optional[str]:
    """Returns the first 12 hex digits of a SHA-256 over the rule files' relative paths and contents, None when
    rules is empty, or "missing" when the path does not exist."""
    if not rules:
        return None
    if os.path.isfile(rules):
        files = [(os.path.basename(rules), rules)]
    elif os.path.isdir(rules):
        files = sorted(
            (os.path.relpath(os.path.join(root, name), rules).replace(os.sep, "/"), os.path.join(root, name))
            for root, _, names in os.walk(rules)
            for name in names
        )
    else:
        return "missing"
    digest = hashlib.sha256()
    for relative, full in files:
        digest.update(relative.encode() + b"\0")
        with open(full, "rb") as f:
            digest.update(hashlib.sha256(f.read()).digest())
    return digest.hexdigest()[:12]


def command(
    path: str,
    limit: int,
    rules: Optional[str] = None,
    container_files: int = 500,
    strings: int = 500,
    yara_matches: int = 500,
    corvus: str = CORVUS,
) -> List[str]:
    """Returns the corvus batch argument list for one file; rules is omitted when empty."""
    args = [
        corvus, "batch", "--file", path, "--json", "--no-index",
        "--time-limit", str(limit),
        "--limit", f"containerFiles={container_files}",
        "--limit", f"strings={strings}",
        "--limit", f"yaraMatches={yara_matches}",
    ]
    if rules:
        args += ["--rules", rules]
    return args
