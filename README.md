# Corvus service for Assemblyline 4

Runs `corvus batch --file <path> --json` ([Corvus](https://github.com/Albasha0x0/Corvus)) on each file and maps the
`corvus.batch/1` document to result sections. Nothing in the file runs; Corvus is offline. The document is attached
as `corvus.batch.json`.

## Result sections

| Section | From the document | Tags and heuristics |
|---|---|---|
| Corvus file summary | `summary`: type, container, entropy, signature; highlights, reader notes, format detail | — |
| Container: *label* | `container`: member paths and details | heuristic 1, signature = container label |
| .NET outline | `summary.assemblies`, `summary.entryPoints` | — |
| Typed strings | `strings`: type, value, count, first location | `network.static.uri`, `network.static.domain`, `network.static.ip`, `network.email.address`, `file.path`, `dynamic.registry_key`, `dynamic.mutex`, `network.user_agent` |
| YARA matches | `yara`: rule, file or member, offset | `file.rule.yara`; heuristic 2, signature = rule name |
| Incomplete reading | sections `partial`, `unavailable`, `error` or `timeout`, with Corvus's limit or reason | — |

- An unfinished step, and a note naming input a step did not read (members past a size cap, rule errors), is
  reported as unknown, never as absent or "no match".
- Corvus 2.5.1 reads one page per step, so a large container can show `partial` at a limit it did not reach; fixed
  in the next Corvus release.
- Heuristics score 0; set scores per signature with `signature_score_map`.
- No document (exit code other than 0 or 124, or not `corvus.batch/1`) is a service error.

## Not mapped

- Extracted files: `corvus.batch/1` lists members without extracting them.
- Il2Cpp type outline, typed strings of bundled assemblies, SBOM and advisories: not in `corvus.batch/1`.

## Configuration

| Setting | Default | Meaning |
|---|---|---|
| `rules_path` | empty | YARA rule file or folder in the container; empty skips YARA. A path that does not exist is logged and YARA is reported as not run. |
| `container_files`, `strings`, `yara_matches` | 500 | `corvus batch --limit` values. |

Time limit: service `timeout` less 45 s, at least half the timeout and 10 s; Corvus is stopped 15 s after it, and
always 5 s before the timeout. The
tool version is the Corvus version plus a digest of the rule files.

## Build

The image installs the Corvus linux-x64 release named by `CORVUS_VERSION`. Its SHA-256 must equal `CORVUS_SHA256`
and the release's `SHA256SUMS` line; change both arguments together.

```sh
docker build --build-arg version=4.7.4.dev0 -t assemblyline-service-corvus:dev .
```

Add YARA rules in a derived image and set `rules_path`.

## Tests

```sh
pip install -r tests/requirements.txt
python -m pytest tests
```

Documents in `tests/documents` were recorded with Corvus 2.5.1 from the self-built inputs in `tests/inputs`, paths
changed to `/tmp/corvus/`. `test_service.py` runs on Linux only.

## License

Apache License 2.0, as is Corvus.
