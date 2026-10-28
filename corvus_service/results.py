"""Maps a corvus.batch/1 document to Assemblyline result sections."""

import re
from typing import Any, Dict, List, Optional, Sequence

from assemblyline_v4_service.common.result import (
    Heuristic,
    ResultJSONSection,
    ResultKeyValueSection,
    ResultSection,
    ResultTableSection,
    ResultTextSection,
    TableRow,
)

SCHEMA = "corvus.batch/1"

HEUR_CONTAINER = 1

# Files named in Files not extracted; the rest are counted.
MAX_NAMED = 100

# Statuses whose section holds everything it was meant to read.
DONE = ("complete", "not_applicable")

# extract_strings value types and their Assemblyline tags; types not listed are shown, not tagged.
STRING_TAGS = {
    "url": "network.static.uri",
    "domain": "network.static.domain",
    "ipv4": "network.static.ip",
    "ipv6": "network.static.ip",
    "email": "network.email.address",
    "file_path": "file.path",
    "registry_key": "dynamic.registry_key",
    "mutex": "dynamic.mutex",
    "user_agent": "network.user_agent",
}


# Reader notes that name input a step did not read, such as members past a size cap.
UNREAD = re.compile(r"\bnot (read|scanned|run)\b|\bthe rest were not\b|\bskipped\b|\btruncated\b", re.IGNORECASE)


class DocumentError(ValueError):
    """The document is not a corvus.batch/1 document."""


def check(document: Any) -> Dict[str, Any]:
    """Returns the document when its schema is corvus.batch/1; raises DocumentError otherwise."""
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        schema = document.get("schema") if isinstance(document, dict) else None
        raise DocumentError(f"expected a {SCHEMA} document, got schema {schema!r}")
    if not isinstance(document.get("sections"), list):
        raise DocumentError(f"the {SCHEMA} document has no sections list")
    return document


def _section(document: Dict[str, Any], name: str) -> Dict[str, Any]:
    for section in document["sections"]:
        if isinstance(section, dict) and section.get("name") == name:
            return section
    return {"name": name, "status": "missing"}


def _result(section: Dict[str, Any]) -> Dict[str, Any]:
    result = section.get("result")
    return result if isinstance(result, dict) else {}


def _items(section: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [i for i in _result(section).get("items") or [] if isinstance(i, dict)]


def _count(section: Dict[str, Any]) -> str:
    """Returns "N" for a complete listing, "N of T" when more rows exist than were read."""
    result, read = _result(section), len(_items(section))
    total = result.get("total")
    if section.get("status") != "complete" and isinstance(total, int) and total > read:
        return f"{read} of {total}"
    return str(read)


def _unread(section: Dict[str, Any]) -> List[str]:
    """Returns the section's notes that name input it did not read."""
    return [n for n in _result(section).get("notes") or [] if isinstance(n, str) and UNREAD.search(n)]


def _incomplete(document: Dict[str, Any]) -> List[str]:
    """Returns one line per section that did not read everything, with Corvus's reason or limit, and one per
    note of a finished section that names input it did not read."""
    lines = []
    for section in document["sections"]:
        if not isinstance(section, dict):
            continue
        name, status = section.get("name", "?"), section.get("status", "?")
        if status in DONE:
            lines += [f"{name}: {note}" for note in _unread(section) if f"{name}: {note}" not in lines]
        elif status == "partial" and section.get("limit"):
            lines.append(f"{name}: {status}; stopped at the {section['limit']} limit")
        else:
            error = section.get("error") if isinstance(section.get("error"), dict) else {}
            lines.append(f"{name}: {status}; {section.get('reason') or error.get('message') or 'no reason given'}")
    return lines


def _summary(document: Dict[str, Any], summary: Dict[str, Any], strings: Dict[str, Any],
             complete: bool) -> ResultSection:
    facts = _result(summary)
    file = document.get("file") or {}
    kv = ResultKeyValueSection("Corvus file summary")
    kv.set_item("Type", file.get("type") or facts.get("type") or "unknown")
    if facts.get("container"):
        kv.set_item("Container", facts["container"])
    if "entropy" in facts:
        kv.set_item("Entropy", facts["entropy"])
    if facts.get("signature"):
        kv.set_item("Signature", facts["signature"])
    if strings.get("status") == "complete" and not _items(strings):
        kv.set_item("Typed strings", "none found")
    kv.set_item("Reading", "complete" if complete else "partial; see Incomplete reading")
    kv.set_item("Corvus", document.get("corvus", "unknown"))

    highlights = [h for h in facts.get("highlights") or [] if isinstance(h, str)]
    if isinstance(facts.get("highlightTotal"), int) and facts["highlightTotal"] > len(highlights):
        highlights.append(f"{facts['highlightTotal'] - len(highlights)} more highlights not shown (summaryHighlights limit).")
    if highlights:
        kv.add_subsection(ResultTextSection("Highlights", body="\n".join(highlights)))
    notes: List[str] = []
    for source in (facts, _result(_section(document, "container"))):
        for note in source.get("notes") or []:
            if isinstance(note, str) and note not in notes:
                notes.append(note)
    if notes:
        kv.add_subsection(ResultTextSection("Reader notes", body="\n".join(notes)))
    if isinstance(facts.get("detail"), dict) and facts["detail"]:
        kv.add_subsection(ResultJSONSection("Format detail", body=facts["detail"]))
    return kv


def _container(summary: Dict[str, Any], container: Dict[str, Any]) -> Optional[ResultSection]:
    items = _items(container)
    if not items:
        return None
    label = _result(container).get("container") or _result(summary).get("container") or "container"
    table = ResultTableSection(f"Container: {label} ({_count(container)} members)")
    for item in items:
        table.add_row(TableRow({"Path": item.get("path"), "Detail": item.get("detail")}))
    table.set_heuristic(Heuristic(HEUR_CONTAINER, signature=label))
    return table


def _outline(summary: Dict[str, Any]) -> Optional[ResultSection]:
    facts = _result(summary)
    assemblies = [a for a in facts.get("assemblies") or [] if isinstance(a, dict)]
    entry_points = [e for e in facts.get("entryPoints") or [] if isinstance(e, str)]
    if not assemblies and not entry_points:
        return None
    noun = "assembly" if len(assemblies) == 1 else "assemblies"
    table = ResultTableSection(f".NET outline ({len(assemblies)} {noun})")
    for a in assemblies:
        row = {k: a.get(k.lower()) for k in ("Path", "Name", "Kind", "Architecture", "Version", "Framework")}
        if a.get("readyToRun"):
            row["ReadyToRun"] = True
        if a.get("merged"):
            row["Merged"] = a["merged"]
        table.add_row(TableRow(row))
    if entry_points:
        table.add_subsection(ResultTextSection("Entry points", body="\n".join(entry_points)))
    return table


def _strings(strings: Dict[str, Any]) -> Optional[ResultSection]:
    items = _items(strings)
    if not items:
        return None
    table = ResultTableSection(f"Typed strings ({_count(strings)})")
    for item in items:
        kind, value = item.get("type"), item.get("value")
        locations = [loc for loc in item.get("locations") or [] if isinstance(loc, str)]
        where = locations[0] if locations else ""
        if len(locations) > 1:
            where += f" (+{len(locations) - 1} more)"
        table.add_row(TableRow({"Type": kind, "Value": value, "Count": item.get("count"), "Location": where}))
        if kind in STRING_TAGS and isinstance(value, str):
            table.add_tag(STRING_TAGS[kind], value)
    return table


def toolchain(facts: Sequence[Any]) -> Optional[ResultSection]:
    """Returns the table of packing and toolchain facts (steps.Fact), each tagged with its tag; None for none."""
    if not facts:
        return None
    table = ResultTableSection(f"Packing and toolchain ({len(facts)})")
    for fact in facts:
        table.add_row(TableRow({"Kind": fact.kind, "Value": fact.value, "Source": fact.source}))
        if fact.tag:
            table.add_tag(fact.tag, fact.value)
    return table


def not_extracted(unlisted: List[str], unadded: List[str], max_extracted: int) -> Optional[ResultSection]:
    """Returns the section naming files past Corvus's page limit and files not added past max_extracted; None
    when there are neither."""
    lines = list(unlisted)
    if unadded:
        lines.append(f"{len(unadded)} files not added: max_extracted is {max_extracted}")
        lines += unadded[:MAX_NAMED]
        if len(unadded) > MAX_NAMED:
            lines.append(f"{len(unadded) - MAX_NAMED} more not named")
    return ResultTextSection("Files not extracted", body="\n".join(lines)) if lines else None


def sections(document: Any, more: Sequence[ResultSection] = (), unread: Sequence[str] = ()) -> List[ResultSection]:
    """Returns the result sections of a corvus.batch/1 document, then more, in display order; raises
    DocumentError for another document. A section Corvus could not finish, and each line of unread, is named under
    Incomplete reading, never shown as empty."""
    document = check(document)
    summary, container = _section(document, "summary"), _section(document, "container")
    strings = _section(document, "strings")
    lines = _incomplete(document) + list(unread)
    complete = document.get("complete") is True and not lines
    out: List[ResultSection] = [_summary(document, summary, strings, complete)]
    for built in (_container(summary, container), _outline(summary), _strings(strings)):
        if built is not None:
            out.append(built)
    out += more
    if lines:
        body = "What these steps did not read is unknown, not absent.\n" + "\n".join(lines)
        out.append(ResultTextSection("Incomplete reading", body=body))
    return out
