import os
import re

import pytest
import yaml

from conftest import ROOT

with open(os.path.join(ROOT, "service_manifest.yml"), encoding="utf-8") as f:
    MANIFEST = yaml.safe_load(f)


def routed(file_type):
    """Returns whether Assemblyline sends a file of this type to the service, by its accepts and rejects."""
    return bool(re.match(MANIFEST["accepts"], file_type)) and not re.match(MANIFEST["rejects"], file_type)


# The types Assemblyline 4.7.4 identify assigns to the files tests/inputs/build.sh writes, and archive/asar, the
# type its rules give an Electron archive.
@pytest.mark.parametrize("file_type", [
    "archive/ar", "archive/asar", "archive/cpio", "archive/zip", "document/installer/windows", "code/javascript",
    "executable/linux/elf64", "executable/linux/pie64", "executable/windows/dll32",
])
def test_a_format_corvus_reads_is_routed_to_the_service(file_type):
    assert routed(file_type)


@pytest.mark.parametrize("file_type", ["text/plain", "archive/7-zip", "document/pdf", "executable/windows/dos"])
def test_a_format_outside_the_list_is_not_routed(file_type):
    assert not routed(file_type)
