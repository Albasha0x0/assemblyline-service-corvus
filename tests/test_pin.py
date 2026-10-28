import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import pin_corvus  # noqa: E402

DOCKERFILE = "FROM base\nARG CORVUS_VERSION=2.7.2\nARG CORVUS_SHA256=" + "a" * 64 + "\nUSER root\n"
NEW = "B" * 64


def test_both_pins_are_set_from_the_listed_archive(tmp_path):
    dockerfile, sums = tmp_path / "Dockerfile", tmp_path / "SHA256SUMS"
    dockerfile.write_text(DOCKERFILE)
    sums.write_text(f"{'0' * 64}  corvus-win-x64.zip\n{NEW}  corvus-linux-x64.tar.gz\n")
    assert pin_corvus.main(["--version", "v2.8.0", "--sums", str(sums), "--dockerfile", str(dockerfile)]) == 0
    assert dockerfile.read_text() == DOCKERFILE.replace("2.7.2", "2.8.0").replace("a" * 64, NEW.lower())


def test_a_bad_version_or_a_missing_pin_is_refused():
    with pytest.raises(ValueError, match="CORVUS_VERSION"):
        pin_corvus.pin(DOCKERFILE, "2.8", NEW)
    with pytest.raises(ValueError, match="0 ARG CORVUS_SHA256 lines"):
        pin_corvus.pin("ARG CORVUS_VERSION=2.7.2\n", "2.8.0", NEW)


def test_sums_without_the_linux_archive_leave_the_dockerfile_unchanged(tmp_path):
    dockerfile, sums = tmp_path / "Dockerfile", tmp_path / "SHA256SUMS"
    dockerfile.write_text(DOCKERFILE)
    sums.write_text(f"{NEW}  corvus-win-x64.zip\n")
    with pytest.raises(ValueError, match="lists no corvus-linux-x64.tar.gz"):
        pin_corvus.main(["--version", "2.8.0", "--sums", str(sums), "--dockerfile", str(dockerfile)])
    assert dockerfile.read_text() == DOCKERFILE
