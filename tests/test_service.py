import json
import os
import stat

import pytest

from conftest import DOCUMENTS

try:
    from corvus_service.corvus import Corvus, CorvusError
except (ImportError, OSError) as e:
    # The service framework loads libc.so.6 at import, so these tests run on Linux only.
    pytest.skip(f"assemblyline_v4_service.common.base does not load here: {e}", allow_module_level=True)


class Request:
    """The parts of ServiceRequest the service uses."""

    def __init__(self, path):
        self.file_path = path
        self.result = None
        self.supplementary = []

    def add_supplementary(self, path, name, description):
        self.supplementary.append((path, name, description))


def fake_corvus(tmp_path, document, code):
    """Writes an executable that prints a recorded document and exits with code, standing in for corvus."""
    script = tmp_path / "corvus"
    body = f"cat '{os.path.join(DOCUMENTS, document + '.json')}'" if document else "echo 'usage' >&2"
    script.write_text(f"#!/bin/sh\n[ \"$1\" = version ] && echo 2.5.1 && exit 0\n{body}\nexit {code}\n")
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


def test_a_document_becomes_sections_and_a_supplementary_file(service):
    corvus = service("single_file_bundle")
    request = Request("/tmp/corvus/hello-bundle.exe")
    corvus.execute(request)
    titles = [s.title_text for s in request.result.sections]
    assert titles[0] == "Corvus file summary"
    assert any(t.startswith("Container: .NET single-file bundle") for t in titles)
    path, name, _ = request.supplementary[0]
    assert name == "corvus.batch.json"
    with open(path, encoding="utf-8") as f:
        assert json.load(f)["schema"] == "corvus.batch/1"
    assert corvus.get_tool_version() == "2.5.1"


def test_a_run_the_time_limit_ended_is_still_reported(service):
    request = Request("/tmp/corvus/zeros.bin")
    service("timeout", code=124).execute(request)
    assert [s.title_text for s in request.result.sections] == ["Corvus file summary", "Incomplete reading"]


def test_a_run_without_a_document_is_a_service_error(service):
    with pytest.raises(CorvusError, match="exited with 2: usage"):
        service(None, code=2).execute(Request("/tmp/corvus/absent"))


def test_the_configured_rules_change_the_tool_version(service, tmp_path):
    rules = tmp_path / "rules.yar"
    rules.write_text("rule a { condition: true }")
    corvus = service("plain_data")
    corvus.config["rules_path"] = str(rules)
    corvus.start()
    assert corvus.get_tool_version().startswith("2.5.1.rules-")


def test_a_missing_rules_path_reads_the_file_without_yara(service, tmp_path):
    corvus = service("plain_data")
    corvus.config["rules_path"] = str(tmp_path / "absent")
    corvus.start()
    args, real = [], corvus.run

    def run(command, kill_after):
        args.extend(command)
        return real(command, kill_after)

    corvus.run = run
    request = Request("/tmp/corvus/zeros.bin")
    corvus.execute(request)
    assert "--rules" not in args
    incomplete = next(s for s in request.result.sections if s.title_text == "Incomplete reading")
    assert incomplete.body.splitlines()[1] == f"yara: not run; rules_path {tmp_path / 'absent'} does not exist"
