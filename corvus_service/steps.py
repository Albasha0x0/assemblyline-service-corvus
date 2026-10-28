"""The corvus calls made after corvus batch --file, in one session: the files Corvus writes out."""

import json
import os
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

UNPACK = "unpack"
EMBEDDED = "embedded"


class Extracted(NamedTuple):
    """A file Corvus wrote, with the name and description it is added under."""

    path: str
    name: str
    description: str


class Outcome(NamedTuple):
    """What the steps wrote: files to add, lines naming files past Corvus's page limit, and one line per step
    that did not finish."""

    files: List[Extracted]
    unlisted: List[str]
    unread: List[str]


def _summary(document: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    """Returns the summary section's result and the container section's status."""
    summary, container = {}, "missing"
    for section in document.get("sections") or []:
        if not isinstance(section, dict):
            continue
        if section.get("name") == "summary" and isinstance(section.get("result"), dict):
            summary = section["result"]
        elif section.get("name") == "container":
            container = section.get("status") or "missing"
    return summary, container


def plan(path: str, document: Dict[str, Any], file_type: str, unpacked: str, embedded: str,
         limit: int) -> List[Tuple[str, Dict[str, Any]]]:
    """Returns the named steps that apply to the file, as corvus batch step records; empty when none applies."""
    summary, container = _summary(document)
    planned = []
    # The summary names no container for a source-mapped script, which unpack_container still reads.
    if container != "not_applicable" or file_type.startswith("code/javascript"):
        planned.append((UNPACK, {"tool": "unpack_container", "args": {
            "path": path, "outputDirectory": unpacked, "extractOnly": True, "limit": limit}}))
    managed = str(summary.get("type") or "").startswith(".NET assembly") or bool(summary.get("assemblies"))
    if managed:
        planned.append((EMBEDDED, {"tool": "extract_embedded", "args": {
            "path": path, "save": True, "outputDirectory": embedded, "limit": limit}}))
    return planned


def read(stdout: str, planned: List[Tuple[str, Dict[str, Any]]]) -> Dict[str, Dict[str, Any]]:
    """Returns each step's output line by step name; a step with no line, or a line that is not JSON, is left out."""
    lines: Dict[str, Dict[str, Any]] = {}
    for text in stdout.splitlines():
        try:
            line = json.loads(text)
        except ValueError:
            continue
        index = line.get("step") if isinstance(line, dict) else None
        if isinstance(index, int) and 1 <= index <= len(planned):
            lines[planned[index - 1][0]] = line
    return lines


def _structured(line: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    structured = line.get("structured") if line else None
    return structured if isinstance(structured, dict) else {}


def _items(line: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [i for i in _structured(line).get("items") or [] if isinstance(i, dict)]


def _members(line: Optional[Dict[str, Any]]) -> List[Extracted]:
    structured = _structured(line)
    base, label = structured.get("outputDirectory"), structured.get("container") or "container"
    files = []
    for item in _items(line):
        path = item.get("path")
        if not isinstance(base, str) or not isinstance(path, str):
            continue
        origin = f", {item['origin']}" if isinstance(item.get("origin"), str) else ""
        files.append(Extracted(os.path.join(base, path), path, f"{label} member{origin}"))
    return files


def _payloads(line: Optional[Dict[str, Any]]) -> List[Extracted]:
    files = []
    for item in _items(line):
        saved = item.get("savedTo")
        if not isinstance(saved, str):
            continue
        chain = " > ".join(e for e in item.get("encoding") or [] if isinstance(e, str))
        decoded = f", decoded from {chain}" if chain else ""
        files.append(Extracted(saved, os.path.basename(saved), f"{item.get('source') or 'embedded content'}{decoded}"))
    return files


def _past_limit(name: str, line: Optional[Dict[str, Any]]) -> List[str]:
    """Returns a line naming how many files Corvus did not list past its page limit, or nothing."""
    structured = _structured(line)
    total, read_ = structured.get("total"), len(_items(line))
    if structured.get("hasMore") and isinstance(total, int) and total > read_:
        return [f"{name}: {total - read_} of {total} files past the page limit of {read_}, not added"]
    return []


# Why a planned step has no output line.
NO_OUTPUT = "corvus wrote no output for it"
NO_TIME = "no time was left after corvus batch --file"


def outcome(lines: Dict[str, Dict[str, Any]], planned: List[Tuple[str, Dict[str, Any]]],
            missing: str = NO_OUTPUT) -> Outcome:
    """Returns the files the steps wrote that exist on disk, the rows past the page limit, and one line per step
    that wrote no output, named with missing, or reported an error."""
    files: List[Extracted] = []
    unlisted: List[str] = []
    unread: List[str] = []
    for name, _ in planned:
        line = lines.get(name)
        if line is None:
            unread.append(f"{name}: not run; {missing}")
            continue
        if line.get("isError"):
            error = line.get("error") if isinstance(line.get("error"), dict) else {}
            unread.append(f"{name}: {error.get('code') or 'error'}; {error.get('message') or 'no reason given'}")
            continue
        found = _members(line) if name == UNPACK else _payloads(line)
        files += [f for f in found if os.path.isfile(f.path)]
        unlisted += _past_limit(name, line)
    return Outcome(files, unlisted, unread)
