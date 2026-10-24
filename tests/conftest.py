import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCUMENTS = os.path.join(ROOT, "tests", "documents")

# Result sections resolve heuristics from the manifest named here.
os.environ["SERVICE_MANIFEST_PATH"] = os.path.join(ROOT, "service_manifest.yml")
sys.path.insert(0, ROOT)


def load(name: str) -> dict:
    with open(os.path.join(DOCUMENTS, name + ".json"), encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def document():
    return load
