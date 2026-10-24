import hashlib
import io
import os
import sys
import tarfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import install_corvus  # noqa: E402

ASSET = "corvus-linux-x64.tar.gz"
DATA = b"archive bytes"
PINNED = hashlib.sha256(DATA).hexdigest()
SUMS = f"{'0' * 64}  corvus-win-x64.zip\r\n{PINNED.upper()}  {ASSET}\r\n"


def archive() -> bytes:
    """A tar.gz holding a corvus file, as the release archive does."""
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        body = b"#!/bin/sh\necho 2.5.1\n"
        info = tarfile.TarInfo("corvus")
        info.size = len(body)
        tar.addfile(info, io.BytesIO(body))
    return out.getvalue()


def test_an_archive_matching_its_pin_and_sha256sums_is_accepted():
    install_corvus.verify(DATA, PINNED, SUMS, ASSET)


def test_an_altered_archive_is_refused():
    with pytest.raises(ValueError, match="checksum mismatch"):
        install_corvus.verify(DATA + b"!", PINNED, SUMS, ASSET)


def test_an_archive_sha256sums_lists_under_another_hash_is_refused():
    # Archive and SHA256SUMS replaced together on the server; only the pin differs.
    data = b"replaced archive"
    sums = f"{hashlib.sha256(data).hexdigest()}  {ASSET}\n"
    with pytest.raises(ValueError, match="checksum mismatch"):
        install_corvus.verify(data, PINNED, sums, ASSET)


def test_a_sha256sums_line_that_differs_from_the_pin_is_refused():
    sums = f"{'1' * 64}  {ASSET}\n"
    with pytest.raises(ValueError, match="not the pinned"):
        install_corvus.verify(DATA, PINNED, sums, ASSET)


def test_an_asset_sha256sums_does_not_list_is_refused():
    with pytest.raises(ValueError, match="lists no corvus-linux-x64.tar.gz"):
        install_corvus.verify(DATA, PINNED, "", ASSET)


def test_the_verified_archive_is_unpacked_with_an_executable_corvus(tmp_path, monkeypatch):
    data = archive()
    pinned = hashlib.sha256(data).hexdigest()
    served = {
        f"{install_corvus.RELEASES}/v2.5.1/{ASSET}": data,
        f"{install_corvus.RELEASES}/v2.5.1/SHA256SUMS": f"{pinned}  {ASSET}\n".encode(),
    }
    monkeypatch.setattr(install_corvus, "fetch", served.__getitem__)
    dest = tmp_path / "corvus"
    assert install_corvus.main(["--version", "2.5.1", "--sha256", pinned, "--dest", str(dest)]) == 0
    assert (dest / "corvus").read_bytes().startswith(b"#!/bin/sh")
    if os.name == "posix":
        assert os.access(dest / "corvus", os.X_OK)


def test_a_download_that_fails_its_pin_writes_nothing(tmp_path, monkeypatch):
    data = archive()
    served = {
        f"{install_corvus.RELEASES}/v2.5.1/{ASSET}": data,
        f"{install_corvus.RELEASES}/v2.5.1/SHA256SUMS": f"{hashlib.sha256(data).hexdigest()}  {ASSET}\n".encode(),
    }
    monkeypatch.setattr(install_corvus, "fetch", served.__getitem__)
    dest = tmp_path / "corvus"
    with pytest.raises(ValueError, match="checksum mismatch"):
        install_corvus.main(["--version", "2.5.1", "--sha256", PINNED, "--dest", str(dest)])
    assert not dest.exists()
