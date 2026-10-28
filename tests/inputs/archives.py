"""Writes app.asar and hello.aab, holding notes.txt and a script, into the folder given."""

import json
import os
import struct
import sys
import zipfile

here, out = os.path.dirname(os.path.abspath(__file__)), sys.argv[1]
with open(os.path.join(here, "notes.txt"), "rb") as f:
    notes = f.read()

# ASAR: a size record, a header record holding the JSON file index, then the file data.
data = b'console.log("https://example.com/api/items");\n'
index = json.dumps({"files": {"main.js": {"size": len(data), "offset": "0"}}}, separators=(",", ":")).encode()
padded = index + b"\0" * (-len(index) % 4)
header = struct.pack("<II", len(padded) + 4, len(index)) + padded
with open(os.path.join(out, "app.asar"), "wb") as f:
    f.write(struct.pack("<II", 4, len(header)) + header + data)

# Android App Bundle: the entries that name the format, and one asset.
with zipfile.ZipFile(os.path.join(out, "hello.aab"), "w") as z:
    z.writestr("BundleConfig.pb", b"")
    z.writestr("base/manifest/AndroidManifest.xml", b"")
    z.writestr("base/assets/notes.txt", notes)
