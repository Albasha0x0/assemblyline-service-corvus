# Corvus service for Assemblyline 4

Runs `corvus batch --file <path> --json` ([Corvus](https://github.com/Albasha0x0/Corvus)) on each file and maps the
`corvus.batch/1` document to result sections. Nothing in the file runs; Corvus is offline. The document is attached
as `corvus.batch.json`.

A second `corvus batch` session then writes out the files Corvus recovers, added as extracted files:

| Step | Runs when | Extracted files |
|---|---|---|
| `unpack_container extractOnly=true` | the summary names a container, or the file is JavaScript | members, by their path in the container |
| `extract_embedded save=true` | the file is or holds .NET assemblies | decoded resources, byte arrays and literals, with their encoding chain |

## Result sections

| Section | From the document | Tags and heuristics |
|---|---|---|
| Corvus file summary | `summary`: type, container, entropy, signature; highlights, reader notes, format detail | — |
| Container: *label* | `container`: member paths and details | heuristic 1, signature = container label |
| .NET outline | `summary.assemblies`, `summary.entryPoints` | — |
| Typed strings | `strings`: type, value, count, first location | `network.static.uri`, `network.static.domain`, `network.static.ip`, `network.email.address`, `file.path`, `dynamic.registry_key`, `dynamic.mutex`, `network.user_agent` |
| Files not extracted | files past `max_extracted`, and files past the `container_files` page limit | — |
| Incomplete reading | sections `partial`, `unavailable`, `error` or `timeout`, with Corvus's limit or reason; steps with an error or no output | — |

- An unfinished step, and a note naming input a step did not read (members past a size cap), is reported as
  unknown, never as absent.
- Heuristics score 0; set scores per signature with `signature_score_map`.
- No document (exit code other than 0 or 124, or not `corvus.batch/1`) is a service error.

## Not mapped

- Il2Cpp type outline, typed strings of bundled assemblies, SBOM and advisories: not in `corvus.batch/1`.

## Configuration

| Setting | Default | Meaning |
|---|---|---|
| `container_files`, `strings` | 500 | `corvus batch --limit` values; `container_files` is also the page limit of the extraction steps. |

- Time limit: service `timeout` less 45 s, at least half the timeout and 10 s. Corvus is stopped 15 s after it,
  and always 5 s before the timeout.
- Extraction steps: the time left before the last 30 s, shared between the steps; none run with less than 10 s left.
- Tool version: the Corvus version.
- YARA: not run here; Assemblyline's YARA service scans the file and every extracted file.

## Build

The image installs the Corvus linux-x64 release named by `CORVUS_VERSION`. Its SHA-256 must equal `CORVUS_SHA256`
and the release's `SHA256SUMS` line; change both arguments together.

```sh
docker build --build-arg version=4.7.4.dev0 -t assemblyline-service-corvus:dev .
```

## Tests

```sh
pip install -r tests/requirements.txt
python -m pytest tests
```

Documents in `tests/documents` were recorded with Corvus 2.5.1 and 2.7.2 from the self-built inputs in
`tests/inputs` (`tests/inputs/build.sh` builds them), paths changed to `/tmp/corvus/`; `*.steps.jsonl` holds the
extraction steps' output lines without their text. `test_service.py` runs on Linux only.

## License

Apache License 2.0, as is Corvus.
