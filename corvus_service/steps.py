"""The corvus calls made after corvus batch --file, in one session: the file's packing and toolchain facts, the
files Corvus writes out and its SBOM."""

import json
import os
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

FACTS = "facts"
UNPACK = "unpack"
EMBEDDED = "embedded"
SBOM = "sbom"

# Packer finding kinds that name a tool; a "suspicious" finding names none.
PACKER_KINDS = ("packing tool", "hardening tool")


class Extracted(NamedTuple):
    """A file Corvus wrote, with the name and description it is added under."""

    path: str
    name: str
    description: str


class Fact(NamedTuple):
    """A packing or toolchain fact, the Assemblyline tag it sets (None for none) and where Corvus read it."""

    kind: str
    value: str
    source: str
    tag: Optional[str]


class Outcome(NamedTuple):
    """What the steps read and wrote: facts, files to add, lines naming files past Corvus's page limit, one line
    per step that did not finish, and the SBOM's path (None when none was written)."""

    facts: List[Fact]
    files: List[Extracted]
    unlisted: List[str]
    unread: List[str]
    sbom: Optional[str]


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


def plan(path: str, document: Dict[str, Any], file_type: str, unpacked: str, embedded: str, sbom: str,
         limit: int) -> List[Tuple[str, Dict[str, Any]]]:
    """Returns the named steps that apply to the file, as corvus batch step records; the facts step always
    applies."""
    summary, container = _summary(document)
    planned = [(FACTS, {"tool": "summarize_file", "args": {"path": path, "view": "all"}})]
    # The summary names no container for a source-mapped script, which unpack_container still reads.
    if container != "not_applicable" or file_type.startswith("code/javascript"):
        planned.append((UNPACK, {"tool": "unpack_container", "args": {
            "path": path, "outputDirectory": unpacked, "extractOnly": True, "limit": limit}}))
    managed = str(summary.get("type") or "").startswith(".NET assembly") or bool(summary.get("assemblies"))
    if managed:
        planned.append((EMBEDDED, {"tool": "extract_embedded", "args": {
            "path": path, "save": True, "outputDirectory": embedded, "limit": limit}}))
    if "dependencies" in (summary.get("views") or []):
        planned.append((SBOM, {"tool": "summarize_file", "args": {
            "path": path, "view": "dependencies", "sbomPath": sbom, "overwrite": True}}))
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


def _list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def facts(line: Optional[Dict[str, Any]]) -> List[Fact]:
    """Returns the packers, transformation tools, compilers and libraries of a summarize_file view=all line, each
    once, in that order; empty for no line."""
    detail = _dict(_structured(line).get("detail"))
    native, found = _dict(detail.get("native")), []
    for packer in map(_dict, _list(native.get("packers"))):
        if packer.get("kind") in PACKER_KINDS and isinstance(packer.get("name"), str):
            evidence = f"{packer['kind']}: {packer.get('evidence')}"
            found.append(Fact("packer", packer["name"], evidence, "technique.packer"))
        elif isinstance(packer.get("evidence"), str):
            found.append(Fact("possible packer", packer["evidence"], "packer heuristics", None))
    for assembly in map(_dict, _list(_dict(detail.get("managed")).get("assemblies"))):
        markers, where = _dict(assembly.get("markers")), str(assembly.get("path") or "the assembly")
        # A transformer finding names the tool its marker list also names, under its own wording.
        names = [_dict(t).get("name") for t in _list(markers.get("transformers"))] or _list(markers.get("tools"))
        found += [Fact("transformation tool", n, where, "technique.obfuscation") for n in names if isinstance(n, str)]
    go = _dict(detail.get("go"))
    if isinstance(go.get("goVersion"), str):
        found.append(Fact("compiler", go["goVersion"], "Go build information", "file.compiler"))
    rust = _dict(detail.get("rust"))
    if isinstance(rust.get("rustcCommit"), str):
        found.append(Fact("compiler", f"rustc {rust['rustcCommit']}", "Rust standard library paths", "file.compiler"))
    image = _dict(native.get("image"))
    found += [Fact("library", n, "imported by the image", "file.lib") for n in _list(image.get("dependencies"))
              if isinstance(n, str)]
    for component in map(_dict, _list(_dict(detail.get("dependencies")).get("components"))):
        value = component.get("purl") or component.get("name")
        if component.get("type") == "library" and isinstance(value, str):
            found.append(Fact("library", value, str(component.get("source") or "dependencies"), "file.lib"))
    seen, unique = set(), []
    for fact in found:
        if (fact.kind, fact.value) not in seen:
            seen.add((fact.kind, fact.value))
            unique.append(fact)
    return unique


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
    """Returns the facts, the files the steps wrote that exist on disk, the rows past the page limit, one line per
    step that wrote no output, named with missing, or reported an error, and the SBOM when it was written."""
    found: List[Fact] = []
    sbom: Optional[str] = None
    files: List[Extracted] = []
    unlisted: List[str] = []
    unread: List[str] = []
    for name, step in planned:
        line = lines.get(name)
        if line is None:
            unread.append(f"{name}: not run; {missing}")
            continue
        if line.get("isError"):
            error = line.get("error") if isinstance(line.get("error"), dict) else {}
            unread.append(f"{name}: {error.get('code') or 'error'}; {error.get('message') or 'no reason given'}")
            continue
        if name == FACTS:
            found = facts(line)
            continue
        if name == SBOM:
            sbom = step["args"]["sbomPath"] if os.path.isfile(step["args"]["sbomPath"]) else None
            if sbom is None:
                unread.append(f"{name}: no file; corvus reported no error and wrote no SBOM")
            continue
        written = _members(line) if name == UNPACK else _payloads(line)
        files += [f for f in written if os.path.isfile(f.path)]
        unlisted += _past_limit(name, line)
    return Outcome(found, files, unlisted, unread, sbom)
