"""The corvus batch command lines and the time limits they run under."""

import os
import shutil
from typing import List, Optional, Tuple

CORVUS = "/opt/corvus/corvus"

# Assemblyline types whose files Corvus reads as such only under these extensions.
EXTENSIONS = {"code/javascript": (".js", ".mjs", ".cjs")}

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


def command(
    path: str,
    limit: int,
    container_files: int = 500,
    strings: int = 500,
    corvus: str = CORVUS,
) -> List[str]:
    """Returns the corvus batch argument list for one file."""
    return [
        corvus, "batch", "--file", path, "--json", "--no-index",
        "--time-limit", str(limit),
        "--limit", f"containerFiles={container_files}",
        "--limit", f"strings={strings}",
    ]


def named(path: str, file_type: str, folder: str) -> str:
    """Returns path, or a link to it in folder under the extension its type needs when the name lacks one; the
    file is copied when a link cannot be made."""
    extensions = EXTENSIONS.get(file_type)
    if not extensions or path.lower().endswith(extensions):
        return path
    target = os.path.join(folder, os.path.basename(path) + extensions[0])
    try:
        os.symlink(path, target)
    except OSError:
        shutil.copyfile(path, target)
    return target


def steps_budget(service_timeout: int, elapsed: float, count: int) -> Optional[Tuple[int, int]]:
    """Returns the per-call timeout and the kill time in seconds for count steps started elapsed seconds into
    the task, or None when less than MIN_TIME_LIMIT is left before the reserve."""
    left = int(service_timeout - RESERVE_SECONDS - elapsed)
    if count < 1 or left < MIN_TIME_LIMIT:
        return None
    kill = max(1, min(left + GRACE_SECONDS, int(service_timeout - STOP_MARGIN_SECONDS - elapsed)))
    return max(1, left // count), kill


def steps_command(steps_file: str, call_timeout: int, corvus: str = CORVUS) -> List[str]:
    """Returns the corvus batch argument list that runs a steps file in one session, each call bounded by
    call_timeout seconds."""
    return [corvus, "batch", steps_file, "--json", "--no-index", "--timeout", str(call_timeout)]
