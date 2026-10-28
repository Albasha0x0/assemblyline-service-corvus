"""Assemblyline service that reads a file with corvus batch, reports its corvus.batch/1 document and adds the
files Corvus writes out."""

import json
import os
import subprocess
import tempfile
import time
from typing import List

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result
from assemblyline_v4_service.common.task import MaxExtractedExceeded

from corvus_service import results, runner, steps

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
            self.tool_version = subprocess.run([self.corvus, "version"], capture_output=True, text=True, timeout=60).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            self.tool_version = "unknown"

    def get_tool_version(self):
        return self.tool_version

    def execute(self, request: ServiceRequest) -> None:
        started = time.monotonic()
        timeout = int(self.service_attributes.timeout)
        limit = runner.time_limit(timeout)
        args = runner.command(
            request.file_path,
            limit,
            container_files=int(self.config.get("container_files", 500)),
            strings=int(self.config.get("strings", 500)),
            corvus=self.corvus,
        )
        document = self.run(args, runner.kill_after(limit, timeout))

        path = os.path.join(self.working_directory, DOCUMENT_NAME)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(document, f, indent=1)
        request.add_supplementary(path, DOCUMENT_NAME, f"{results.SCHEMA} document written by Corvus")

        outcome = self.run_steps(request, document, timeout, time.monotonic() - started)
        max_extracted = int(request.max_extracted or 0)
        unadded = self.add_extracted(request, outcome.files)
        more = [s for s in (results.not_extracted(outcome.unlisted, unadded, max_extracted),) if s is not None]

        result = Result()
        for section in results.sections(document, more, outcome.unread):
            result.add_section(section)
        request.result = result

    def run_steps(self, request: ServiceRequest, document, timeout: int, elapsed: float) -> steps.Outcome:
        """Runs the steps that apply to the file in one corvus session within the time left; a step that did not
        finish is named in the outcome, never raised."""
        work = self.working_directory
        # Corvus lists up to container_files; files past max_extracted are named, not added.
        limit = int(self.config.get("container_files", 500))
        unpacked = tempfile.mkdtemp(prefix="unpacked-", dir=work)
        embedded = tempfile.mkdtemp(prefix="embedded-", dir=work)
        planned = steps.plan(request.file_path, document, request.file_type or "", unpacked, embedded, limit)
        if not planned:
            return steps.Outcome([], [], [])
        budget = runner.steps_budget(timeout, elapsed, len(planned))
        if budget is None:
            return steps.outcome({}, planned, steps.NO_TIME)
        steps_file = os.path.join(work, "corvus.steps.jsonl")
        with open(steps_file, "w", encoding="utf-8") as f:
            f.writelines(json.dumps(step) + "\n" for _, step in planned)
        call_timeout, kill = budget
        missing = steps.NO_OUTPUT
        try:
            stdout = subprocess.run(runner.steps_command(steps_file, call_timeout, self.corvus),
                                    capture_output=True, text=True, timeout=kill).stdout
        except subprocess.TimeoutExpired as e:
            # The lines written before the kill are kept.
            stdout = e.stdout.decode("utf-8", "replace") if isinstance(e.stdout, bytes) else e.stdout or ""
            missing = f"corvus was stopped after {kill} s"
        return steps.outcome(steps.read(stdout, planned), planned, missing)

    @staticmethod
    def add_extracted(request: ServiceRequest, files: List[steps.Extracted]) -> List[str]:
        """Adds files in order until max_extracted is reached; returns the names of the files not added."""
        for index, file in enumerate(files):
            try:
                request.add_extracted(file.path, file.name, file.description)
            except MaxExtractedExceeded:
                return [f.name for f in files[index:]]
        return []

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
