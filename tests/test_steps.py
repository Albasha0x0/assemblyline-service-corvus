import json
import os

from conftest import DOCUMENTS, load
from corvus_service import steps


def recorded(name, root=None):
    """Returns a recording's step lines; root replaces the recorded /tmp/corvus/rec/<name> folder."""
    with open(os.path.join(DOCUMENTS, name + ".steps.jsonl"), encoding="utf-8") as f:
        text = f.read()
    if root is not None:
        text = text.replace(f"/tmp/corvus/rec/{name}", str(root).replace("\\", "/"))
    return [json.loads(line) for line in text.splitlines()]


def planned(name, file_type=""):
    return steps.plan("/tmp/corvus/f", load(name), file_type, "/out/unpacked", "/out/embedded", 100)


def written(root, lines):
    """Creates every file the lines name under root, as Corvus would have written them."""
    for line in lines:
        structured = line["structured"]
        for item in structured["items"]:
            path = item.get("savedTo") or os.path.join(structured["outputDirectory"], item["path"])
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write("x")


def by_name(lines, plan):
    return steps.read("\n".join(json.dumps(line) for line in lines), plan)


def facts(name):
    """Returns the facts of a recording's first line, the summarize_file view=all step."""
    return [(f.kind, f.value, f.tag) for f in steps.facts(recorded(name)[0])]


def test_every_file_is_read_with_all_summary_views():
    assert planned("packed_elf") == [(steps.FACTS, {"tool": "summarize_file", "args": {
        "path": "/tmp/corvus/f", "view": "all"}})]


def test_a_container_is_unpacked_into_the_given_folder_without_loading():
    assert planned("debian_package")[1:] == [(steps.UNPACK, {"tool": "unpack_container", "args": {
        "path": "/tmp/corvus/f", "outputDirectory": "/out/unpacked", "extractOnly": True, "limit": 100}})]


def test_a_dotnet_assembly_has_its_embedded_content_decoded_and_saved():
    assert [(n, s["tool"], s["args"]["save"]) for n, s in planned("encoded_text")[1:]] == [
        (steps.EMBEDDED, "extract_embedded", True)]


def test_a_script_is_unpacked_although_the_summary_names_no_container():
    assert [n for n, _ in planned("source_map", "code/javascript")] == [steps.FACTS, steps.UNPACK]
    assert [n for n, _ in planned("source_map")] == [steps.FACTS]


def test_members_are_named_by_their_path_in_the_container(tmp_path):
    lines = recorded("debian_package", tmp_path)
    written(tmp_path, lines[1:])
    plan = planned("debian_package")
    out = steps.outcome(by_name(lines, plan), plan)
    assert [(f.name, f.description) for f in out.files] == [
        ("DEBIAN/control", "debian package member, debian package control.tar.zst"),
        ("usr/share/hello/notes.txt", "debian package member, debian package data.tar.zst"),
    ]
    assert out.files[1].path == os.path.join(str(tmp_path).replace("\\", "/"), "unpacked", "usr/share/hello/notes.txt")
    assert out.unlisted == [] and out.unread == []


def test_a_decoded_payload_names_its_source_and_encoding(tmp_path):
    lines = recorded("encoded_text", tmp_path)
    written(tmp_path, lines[1:])
    plan = planned("encoded_text")
    out = steps.outcome(by_name(lines, plan), plan)
    assert [(f.name, f.description) for f in out.files] == [
        ("embedded_01.txt", "string const Settings.Defaults::Encoded, decoded from base64"),
        ("embedded_02.txt", "string Settings.Defaults::Text() @IL_0005, decoded from base64"),
    ]


def test_a_file_that_is_not_on_disk_is_not_added(tmp_path):
    plan = planned("debian_package")
    assert steps.outcome(by_name(recorded("debian_package", tmp_path), plan), plan).files == []


def test_members_past_the_page_limit_are_named_as_not_added(tmp_path):
    lines = recorded("debian_package", tmp_path)
    lines[1]["structured"].update({"total": 5, "hasMore": True})
    plan = planned("debian_package")
    assert steps.outcome(by_name(lines, plan), plan).unlisted == [
        "unpack: 3 of 5 files past the page limit of 2, not added"]


def test_a_step_without_output_is_reported_as_not_run_with_the_reason():
    plan = planned("debian_package")
    assert steps.outcome({}, plan).unread == [
        "facts: not run; corvus wrote no output for it", "unpack: not run; corvus wrote no output for it"]
    assert steps.outcome({}, plan, steps.NO_TIME).unread[1] == (
        "unpack: not run; no time was left after corvus batch --file")


def test_a_step_error_is_reported_with_its_code_and_message():
    plan = planned("debian_package")
    line = {"step": 2, "isError": True, "error": {"code": "timeout", "message": "the call took over 9 s"}}
    assert steps.outcome(by_name([line], plan), plan).unread[1:] == ["unpack: timeout; the call took over 9 s"]


def test_lines_that_are_not_json_or_name_no_planned_step_are_ignored():
    plan = planned("debian_package")
    assert steps.read('progress\n{"step": 3}\n{"step": 2, "isError": false}', plan) == {
        steps.UNPACK: {"step": 2, "isError": False}}


def test_a_packing_tool_is_tagged_as_a_packer():
    assert facts("packed_elf") == [("packer", "UPX", "technique.packer")]


def test_a_transformation_tool_is_tagged_as_obfuscation_once():
    assert facts("marked_assembly") == [("transformation tool", "ConfuserEx", "technique.obfuscation")]


def test_a_go_program_names_its_compiler_and_libraries():
    assert facts("go_program") == [("compiler", "go1.18.1", "file.compiler"),
                                   ("library", "pkg:golang/stdlib@1.18.1", "file.lib")]


def test_a_possible_packer_is_shown_without_a_tag():
    line = {"structured": {"detail": {"native": {"packers": [
        {"name": "unknown packer", "kind": "suspicious", "evidence": "code section .text has entropy 7.90"}]}}}}
    assert [(f.kind, f.value, f.tag) for f in steps.facts(line)] == [
        ("possible packer", "code section .text has entropy 7.90", None)]


def test_the_libraries_an_image_imports_are_tagged_once():
    line = {"structured": {"detail": {"native": {"image": {"dependencies": ["libc.so.6", "libc.so.6"]}}}}}
    assert [(f.kind, f.value, f.tag) for f in steps.facts(line)] == [("library", "libc.so.6", "file.lib")]
