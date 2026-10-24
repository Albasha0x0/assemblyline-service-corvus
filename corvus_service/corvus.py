"""Assemblyline service that reads a file with corvus batch and reports its corvus.batch/1 document."""

import json
import os
import subprocess

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result

from corvus_service import results, runner

DOCUMENT_NAME = "corvus.batch.json"


class CorvusError(RuntimeError):
    """corvus batch exited without writing a document."""


class Corvus(ServiceBase):
    """Runs corvus batch on the submitted file and maps its document to result sections."""

    def __init__(self, config=None):
        super().__init__(config)
        self.corvus = os.environ.get("CORVUS_PATH", runner.CORVUS)
        self.tool_version = None

    def start(self):
        # Read once: Assemblyline asks for the tool version on every task and keys its result cache on it.
        try:
            corvus = subprocess.run([self.corvus, "version"], capture_output=True, text=True, timeout=60).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            corvus = "unknown"
        rules = runner.rules_digest(self.config.get("rules_path") or None)
        self.tool_version = f"{corvus}.rules-{rules}" if rules else corvus
        if self.rules_missing():
            self.log.warning(f"{self.rules_missing()}; files are read without YARA")

    def rules_missing(self):
        """Returns why the configured rules_path is not passed to Corvus, or None when it exists or is empty."""
        rules = self.config.get("rules_path") or None
        return f"rules_path {rules} does not exist" if rules and not os.path.exists(rules) else None

    def get_tool_version(self):
        return self.tool_version

    def execute(self, request: ServiceRequest) -> None:
        timeout = int(self.service_attributes.timeout)
        limit = runner.time_limit(timeout)
        rules_missing = self.rules_missing()
        args = runner.command(
            request.file_path,
            limit,
            rules=None if rules_missing else self.config.get("rules_path") or None,
            container_files=int(self.config.get("container_files", 500)),
            strings=int(self.config.get("strings", 500)),
            yara_matches=int(self.config.get("yara_matches", 500)),
            corvus=self.corvus,
        )
        document = self.run(args, runner.kill_after(limit, timeout))

        path = os.path.join(self.working_directory, DOCUMENT_NAME)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(document, f, indent=1)
        request.add_supplementary(path, DOCUMENT_NAME, f"{results.SCHEMA} document written by Corvus")

        result = Result()
        for section in results.sections(document, rules_missing):
            result.add_section(section)
        request.result = result

    def run(self, args, kill_after: int):
        """Returns the parsed document; raises CorvusError when Corvus wrote none, so the file is reported as a
        service error rather than as read."""
        try:
            done = subprocess.run(args, capture_output=True, text=True, timeout=kill_after)
        except subprocess.TimeoutExpired as e:
            raise CorvusError(f"corvus batch did not exit within {kill_after} s") from e
        if done.returncode not in (runner.EXIT_OK, runner.EXIT_TIMEOUT):
            raise CorvusError(f"corvus batch exited with {done.returncode}: {done.stderr.strip()[-2000:]}")
        try:
            return results.check(json.loads(done.stdout))
        except (ValueError, results.DocumentError) as e:
            raise CorvusError(f"corvus batch wrote no {results.SCHEMA} document: {e}") from e
