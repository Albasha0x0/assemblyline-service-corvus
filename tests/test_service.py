import json
import stat
import sys

import pytest

from conftest import DOCUMENTS

try:
    from assemblyline_v4_service.common.task import MaxExtractedExceeded
    from corvus_service.corvus import Corvus, CorvusError
except (ImportError, OSError) as e:
    # The service framework loads libc.so.6 at import, so these tests run on Linux only.
    pytest.skip(f"assemblyline_v4_service.common.base does not load here: {e}", allow_module_level=True)


class Request:
    """The parts of ServiceRequest the service uses; add_extracted refuses past max_extracted, as Task does."""

    def __init__(self, path, file_type="", max_extracted=0):
        self.file_path = path
        self.file_type = file_type
        self.max_extracted = max_extracted
        self.result = None
        self.supplementary = []
        self.extracted = []
        self.partial_result = False

    def partial(self):
        self.partial_result = True

    def add_supplementary(self, path, name, description):
        self.supplementary.append((path, name, description))

    def add_extracted(self, path, name, description):
        if self.max_extracted and len(self.extracted) >= self.max_extracted:
            raise MaxExtractedExceeded
        with open(path, encoding="utf-8") as f:
            self.extracted.append((name, description, f.read()))
        return True


# Stands in for corvus: prints a recorded document for batch --file, and for a steps file prints the recorded
# step lines with their folders moved to the ones asked for, writing each file a line names and the SBOM.
FAKE = """#!{python}
import json, os, sys
args, documents, name = sys.argv[1:], {documents!r}, {document!r}
if args[:1] == ["version"]:
    print("2.7.2"); sys.exit(0)
if "--file" in args:
    if name is None:
        print("usage", file=sys.stderr); sys.exit(2)
    print(open(os.path.join(documents, name + ".json"), encoding="utf-8").read()); sys.exit({code})
recording = os.path.join(documents, f"{{name}}.steps.jsonl")
recorded = [json.loads(l) for l in open(recording, encoding="utf-8")] if os.path.exists(recording) else []
for l in recorded:
    l["view"] = (l["structured"] or {{}}).get("view")
for index, text in enumerate(open(args[1], encoding="utf-8"), 1):
    step = json.loads(text)
    line = next((l for l in recorded if l["tool"] == step["tool"] and l["view"] == step["args"].get("view")), None)
    if line is None:
        continue
    folder = line["structured"].get("outputDirectory")
    if folder:
        line = json.loads(json.dumps(line).replace(folder, step["args"]["outputDirectory"]))
    line["step"] = index
    if "sbomPath" in step["args"]:
        open(step["args"]["sbomPath"], "w", encoding="utf-8").write("{{}}")
    out = line["structured"]
    for item in out.get("items", []) if folder else []:
        path = item.get("savedTo") or os.path.join(out["outputDirectory"], item["path"])
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "w", encoding="utf-8").write(item.get("sha256", ""))
    print(json.dumps(line))
"""


def fake_corvus(tmp_path, document, code):
    """Writes an executable that replays a recording and exits with code, standing in for corvus."""
    script = tmp_path / "corvus"
    script.write_text(FAKE.format(python=sys.executable, documents=DOCUMENTS, document=document, code=code))
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


@pytest.fixture
def service(tmp_path, monkeypatch):
    def make(document, code=0):
        monkeypatch.setenv("TASKING_DIR", str(tmp_path))
        monkeypatch.setenv("CORVUS_PATH", fake_corvus(tmp_path, document, code))
        corvus = Corvus()
        corvus.start()
        return corvus
    return make


def titles(request):
    return [s.title_text for s in request.result.sections]


def test_a_document_becomes_sections_and_a_supplementary_file(service):
    corvus = service("single_file_bundle")
    request = Request("/tmp/corvus/hello-bundle.exe")
    corvus.execute(request)
    assert titles(request)[0] == "Corvus file summary"
    assert any(t.startswith("Container: .NET single-file bundle") for t in titles(request))
    path, name, _ = request.supplementary[0]
    assert name == "corvus.batch.json"
    with open(path, encoding="utf-8") as f:
        assert json.load(f)["schema"] == "corvus.batch/1"
    assert corvus.get_tool_version() == "2.7.2"


def test_a_run_the_time_limit_ended_is_still_reported(service):
    request = Request("/tmp/corvus/zeros.bin")
    service("timeout", code=124).execute(request)
    assert titles(request) == ["Corvus file summary", "Incomplete reading"]
    assert request.partial_result


def test_a_run_without_a_document_is_a_service_error(service):
    with pytest.raises(CorvusError, match="exited with 2: usage"):
        service(None, code=2).execute(Request("/tmp/corvus/absent"))



def test_container_members_are_added_as_extracted_files(service):
    request = Request("/tmp/corvus/hello.deb", "archive/ar")
    service("debian_package").execute(request)
    assert [(n, d) for n, d, _ in request.extracted] == [
        ("DEBIAN/control", "debian package member, debian package control.tar.zst"),
        ("usr/share/hello/notes.txt", "debian package member, debian package data.tar.zst"),
    ]
    assert "Incomplete reading" not in titles(request)
    assert not request.partial_result


def test_a_decoded_payload_is_added_as_an_extracted_file(service):
    request = Request("/tmp/corvus/Settings.dll", "executable/windows/dll32")
    service("encoded_text").execute(request)
    assert [n for n, _, _ in request.extracted] == ["embedded_01.txt", "embedded_02.txt"]


def test_files_past_max_extracted_are_named_in_their_own_section(service):
    request = Request("/tmp/corvus/hello.deb", "archive/ar", max_extracted=1)
    service("debian_package").execute(request)
    assert [n for n, _, _ in request.extracted] == ["DEBIAN/control"]
    section = next(s for s in request.result.sections if s.title_text == "Files not extracted")
    assert section.body.splitlines() == ["1 files not added: max_extracted is 1", "usr/share/hello/notes.txt"]


def test_a_step_corvus_did_not_answer_is_named_under_incomplete_reading(service):
    request = Request("/tmp/corvus/hello-bundle.exe", "executable/windows/pe64")
    service("single_file_bundle").execute(request)
    incomplete = next(s for s in request.result.sections if s.title_text == "Incomplete reading")
    assert "unpack: not run; corvus wrote no output for it" in incomplete.body.splitlines()


def test_a_packer_corvus_names_is_tagged(service):
    request = Request("/tmp/corvus/hello-packed", "executable/linux/elf64")
    service("packed_elf").execute(request)
    section = next(s for s in request.result.sections if s.title_text == "Packing and toolchain (1)")
    assert section.tags == {"technique.packer": ["UPX"]}


def test_the_sbom_is_attached_as_a_supplementary_file(service):
    request = Request("/tmp/corvus/hello-go", "executable/linux/elf64")
    service("go_program").execute(request)
    assert [name for _, name, _ in request.supplementary] == ["corvus.batch.json", "corvus.cdx.json"]


def test_a_step_that_did_not_finish_marks_the_result_partial(service):
    request = Request("/tmp/corvus/hello-bundle.exe", "executable/windows/pe64")
    service("single_file_bundle").execute(request)
    assert request.partial_result
