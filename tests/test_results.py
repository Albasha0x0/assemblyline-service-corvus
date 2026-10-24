import copy
import json

import pytest

from corvus_service import results


def titled(sections, prefix):
    found = [s for s in sections if s.title_text.startswith(prefix)]
    assert len(found) == 1, [s.title_text for s in sections]
    return found[0]


def titles(sections):
    return [s.title_text for s in sections]


def rows(section):
    return json.loads(section.body)


def summary(sections):
    return json.loads(titled(sections, "Corvus file summary").body)


def sub(section, title):
    return next(s for s in section.subsections if s.title_text == title)


def test_a_single_file_bundle_lists_its_members_under_the_container_heuristic(document):
    sections = results.sections(document("single_file_bundle"))
    container = titled(sections, "Container: .NET single-file bundle")
    assert container.title_text.endswith("(3 members listed, not extracted)")
    assert [r["Path"] for r in rows(container)] == ["Hello.dll", "Hello.runtimeconfig.json", "Hello.deps.json"]
    assert container.heuristic.heur_id == results.HEUR_CONTAINER
    assert container.heuristic.signatures == {".NET single-file bundle": 1}
    assert summary(sections)["Container"] == ".NET single-file bundle"


def test_the_bundle_notes_are_shown_once(document):
    kv = titled(results.sections(document("single_file_bundle")), "Corvus file summary")
    assert sub(kv, "Reader notes").body.splitlines() == ["Single-file bundle v6.0, id zwMCnDl4MUYs, 3 files."]
    assert sub(kv, "Highlights").body == "Network values: 1 url, 1 domain."


def test_the_dotnet_outline_lists_assemblies_and_entry_points(document):
    outline = titled(results.sections(document("single_file_bundle")), ".NET outline (1 assembly)")
    assert rows(outline) == [{"Path": "Hello.dll", "Name": "Hello", "Kind": "console application",
                              "Architecture": "x64", "Version": "1.0.0.0", "Framework": ".NETCoreApp,Version=v10.0"}]
    assert sub(outline, "Entry points").body == "Main: Hello.Program::Main()"


def test_yara_matches_name_the_rule_and_where_it_matched(document):
    yara = titled(results.sections(document("single_file_bundle")), "YARA matches")
    assert [(r["Rule"], r["Where"]) for r in rows(yara)] == [("names_the_endpoint", "the file"), ("names_the_endpoint", "Hello.dll")]
    assert yara.tags == {"file.rule.yara": ["names_the_endpoint"]}
    assert yara.heuristic.heur_id == results.HEUR_YARA
    assert yara.heuristic.signatures == {"names_the_endpoint": 2}


def test_a_zip_member_match_is_named_by_its_member_path(document):
    yara = titled(results.sections(document("zip_with_rules")), "YARA matches")
    assert [(r["Rule"], r["Where"]) for r in rows(yara)] == [("names_the_fixture", "the file"), ("names_the_fixture", "notes.txt")]


def test_typed_strings_are_tagged_by_their_type(document):
    sections = results.sections(document("dotnet_strings"))
    strings = titled(sections, "Typed strings (2)")
    assert [(r["Type"], r["Value"]) for r in rows(strings)] == [("url", "https://example.com/api/items"), ("domain", "example.com")]
    assert rows(strings)[0]["Location"] == "Hello.Program::get_Endpoint() @IL_0000"
    assert strings.tags == {"network.static.uri": ["https://example.com/api/items"], "network.static.domain": ["example.com"]}


def test_an_assembly_with_no_typed_strings_says_none_were_found(document):
    sections = results.sections(document("dotnet_assembly"))
    assert summary(sections)["Typed strings"] == "none found"
    assert not any(t.startswith("Typed strings") for t in titles(sections))


def test_a_complete_reading_has_no_incomplete_section(document):
    sections = results.sections(document("plain_data"))
    assert titles(sections) == ["Corvus file summary"]
    kv = summary(sections)
    assert kv["Reading"] == "complete"
    assert kv["YARA"] == "not run: no rules_path configured"
    assert "Not a known container (data) and no embedded .NET images were found." in sub(sections[0], "Reader notes").body


def test_a_container_over_its_limit_shows_the_rows_read_and_names_the_limit(document):
    sections = results.sections(document("container_partial"))
    container = titled(sections, "Container: zip archive")
    assert "(1 of 2 members listed, not extracted)" in container.title_text
    incomplete = titled(sections, "Incomplete reading").body.splitlines()
    assert incomplete[0] == "What these steps did not read is unknown, not absent."
    assert incomplete[1:] == ["container: partial; stopped at the containerFiles limit"]
    assert summary(sections)["Reading"] == "partial; see Incomplete reading"


def test_unavailable_yara_is_named_and_never_shown_as_no_match(document):
    sections = results.sections(document("yara_unavailable"))
    assert "YARA" not in summary(sections)
    assert not any(t.startswith("YARA") for t in titles(sections))
    line = titled(sections, "Incomplete reading").body.splitlines()[1]
    assert line.startswith("yara: unavailable; ") and "CORVUS_WORKER_HOST=0" in line


def test_a_timed_out_run_reports_every_unfinished_step(document):
    sections = results.sections(document("timeout"))
    assert titles(sections) == ["Corvus file summary", "Incomplete reading"]
    assert summary(sections)["Type"] == "unknown"
    lines = titled(sections, "Incomplete reading").body.splitlines()[1:]
    assert [line.split(";")[0] for line in lines] == ["summary: timeout", "container: timeout", "strings: timeout"]


def test_an_error_section_is_named_with_its_message(document):
    doc = copy.deepcopy(document("dotnet_assembly"))
    doc["complete"] = False
    strings = next(s for s in doc["sections"] if s["name"] == "strings")
    strings.clear()
    strings.update({"name": "strings", "tool": "extract_strings", "status": "error",
                    "error": {"code": "internal", "message": "the reader failed"}})
    sections = results.sections(doc)
    assert "Typed strings" not in summary(sections)
    assert titled(sections, "Incomplete reading").body.splitlines()[1:] == ["strings: error; the reader failed"]


@pytest.mark.parametrize("doc", [None, [], {"schema": "corvus.batch/2", "sections": []}, {"schema": "corvus.batch/1"}])
def test_a_document_of_another_schema_is_refused(doc):
    with pytest.raises(results.DocumentError):
        results.sections(doc)


def test_capped_highlights_name_how_many_were_not_shown(document):
    doc = copy.deepcopy(document("single_file_bundle"))
    next(s for s in doc["sections"] if s["name"] == "summary")["result"]["highlightTotal"] = 3
    kv = titled(results.sections(doc), "Corvus file summary")
    assert sub(kv, "Highlights").body.splitlines() == [
        "Network values: 1 url, 1 domain.", "2 more highlights not shown (summaryHighlights limit)."]


def test_strings_over_their_limit_show_how_many_of_the_total_were_read(document):
    doc = copy.deepcopy(document("dotnet_strings"))
    doc["complete"] = False
    strings = next(s for s in doc["sections"] if s["name"] == "strings")
    strings.update({"status": "partial", "limit": "strings"})
    strings["result"].update({"total": 7, "hasMore": True})
    sections = results.sections(doc)
    assert titled(sections, "Typed strings").title_text == "Typed strings (2 of 7)"
    assert titled(sections, "Incomplete reading").body.splitlines()[1:] == ["strings: partial; stopped at the strings limit"]


def test_a_type_without_an_assemblyline_tag_is_shown_but_not_tagged(document):
    doc = copy.deepcopy(document("dotnet_strings"))
    strings = next(s for s in doc["sections"] if s["name"] == "strings")
    strings["result"]["items"].append({"type": "named_pipe", "value": r"\.\pipe\fixture", "count": 1, "locations": []})
    table = titled(results.sections(doc), "Typed strings")
    assert rows(table)[-1] == {"Type": "named_pipe", "Value": r"\.\pipe\fixture", "Count": 1, "Location": ""}
    assert set(table.tags) == {"network.static.uri", "network.static.domain"}


def yara_without_rows(document, *notes):
    doc = copy.deepcopy(document("zip_with_rules"))
    yara = next(s for s in doc["sections"] if s["name"] == "yara")
    yara["result"].update({"items": [], "total": 0})
    yara["result"]["notes"] = [yara["result"]["notes"][0], *notes]
    return doc


def test_yara_with_no_rows_and_every_member_scanned_says_no_rule_matched(document):
    sections = results.sections(yara_without_rows(document))
    assert summary(sections)["YARA"].startswith("no rule matched (YARA-X 1.22.0: 3 rules from 1 file; 2 container members scanned")
    assert summary(sections)["Reading"] == "complete"
    assert not any(t.startswith(("YARA matches", "Incomplete reading")) for t in titles(sections))


def test_yara_members_left_unscanned_go_to_incomplete_reading_not_under_no_match(document):
    note = "Container members not read: the file is larger than 256 MB; it was scanned as one file."
    sections = results.sections(yara_without_rows(document, note))
    assert summary(sections)["YARA"] == "no rule matched in what was read; see Incomplete reading"
    assert summary(sections)["Reading"] == "partial; see Incomplete reading"
    assert titled(sections, "Incomplete reading").body.splitlines()[1:] == [f"yara: {note}"]


def test_a_missing_rules_path_reports_yara_as_not_run_with_the_reason(document):
    sections = results.sections(document("plain_data"), rules_missing="rules_path /opt/rules does not exist")
    assert summary(sections)["YARA"] == "not run: rules_path /opt/rules does not exist"
    assert titled(sections, "Incomplete reading").body.splitlines()[1:] == ["yara: not run; rules_path /opt/rules does not exist"]
