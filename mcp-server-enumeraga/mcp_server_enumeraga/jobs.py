"""Job records for detached scans, and the background pull-then-launch flow.

A job file lives in the scan's output directory so that a later status call can
find a scan that was started by an earlier server process. Secrets are held in
memory only and are never written to the file.
"""

import asyncio
import json
import os
import re
import secrets as _secrets
import sys
import tempfile
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable

from .scan_status import redact

JOB_FILE = ".enumeraga-job.json"
ACTIVE_STAGES = ("pulling_image", "starting")
MAX_ERROR_CHARS = 500
PULL_TIMEOUT_S = 1800
RUN_TIMEOUT_S = 120
INSPECT_TIMEOUT_S = 5

_CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{12,64}$")
_OPTIONAL_FIELDS = ("container_id", "error")
# The only shapes a scan id and its container name can take. new_scan_id and
# container_name_for are the sole producers; anything else read back from disk
# is tampered with or stale and must never reach a docker command line.
SCAN_ID_PATTERN = re.compile(r"^enum-[0-9a-f]{12}$")
CONTAINER_NAME_PATTERN = re.compile(r"^enumeraga-enum-[0-9a-f]{12}$")

RunFn = Callable[..., Awaitable[str]]


def new_scan_id() -> str:
    return "enum-" + _secrets.token_hex(6)


def container_name_for(scan_id: str) -> str:
    """The container name a detached scan with this id runs under."""
    return f"enumeraga-{scan_id}"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Job:
    scan_id: str
    kind: str
    key: str
    target: str
    image: str
    output_dir: str
    stage: str
    created_at: str
    container_name: str
    container_id: str | None = None
    error: str | None = None
    secrets: frozenset[str] = field(default_factory=frozenset, repr=False)

    def __post_init__(self) -> None:
        self.secrets = frozenset(s for s in self.secrets if s and s.strip())

    def to_dict(self) -> dict:
        return {
            f.name: getattr(self, f.name) for f in fields(self) if f.name != "secrets"
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Job":
        """Build a Job from untrusted data; raise ValueError on a wrong shape."""
        names = {f.name for f in fields(cls)} - {"secrets"}
        values = {}
        for name in names:
            value = data.get(name)
            if name in _OPTIONAL_FIELDS:
                if value is not None and not isinstance(value, str):
                    raise ValueError(f"{name} must be a string or null")
            elif not isinstance(value, str):
                raise ValueError(f"{name} must be a string")
            values[name] = value
        if not SCAN_ID_PATTERN.match(values["scan_id"]):
            raise ValueError("scan_id is not a scan id this server issues")
        # Derived, never trusted: a tampered or stale file could otherwise point
        # docker inspect and docker logs at any container, or start the name with
        # '-' and have docker read it as an option.
        values["container_name"] = container_name_for(values["scan_id"])
        return cls(**values)


class JobStore:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self.tasks: set[asyncio.Task] = set()
        self._warned_save = False

    def add(self, job: Job) -> None:
        self._jobs[job.scan_id] = job

    def get(self, scan_id: str) -> Job | None:
        return self._jobs.get(scan_id)

    def active_for_key(self, key: str) -> Job | None:
        for job in self._jobs.values():
            if job.key == key and job.stage in ACTIVE_STAGES:
                return job
        return None

    def save(self, job: Job) -> None:
        """Write the job file atomically. Failures are logged once and swallowed."""
        tmp_name = None
        try:
            directory = Path(job.output_dir)
            fd, tmp_name = tempfile.mkstemp(dir=directory, prefix=".enumeraga-job-")
            with os.fdopen(fd, "w") as fh:
                json.dump(job.to_dict(), fh)
            os.replace(tmp_name, directory / JOB_FILE)
        except Exception as exc:
            if tmp_name:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
            if not self._warned_save:
                self._warned_save = True
                print(
                    f"enumeraga: could not write job file in {job.output_dir}: {exc}",
                    file=sys.stderr,
                )

    def load_from_dir(self, path: Path) -> tuple[Job | None, bool]:
        """Return (job, orphaned). The in-memory copy wins over the file."""
        try:
            data = json.loads((Path(path) / JOB_FILE).read_text())
            if not isinstance(data, dict):
                return None, False
            disk = Job.from_dict(data)
            disk.output_dir = str(path)
            memory = self._jobs.get(disk.scan_id)
            if memory is not None and Path(memory.output_dir) == Path(path):
                return memory, False
            return disk, disk.stage in ACTIVE_STAGES
        except Exception:
            return None, False


def detach_args(cmd: list[str], scan_id: str) -> list[str]:
    i = cmd.index("run") + 1
    return cmd[:i] + [
        "-d",
        "--name", container_name_for(scan_id),
        "--label", f"enumeraga.scan_id={scan_id}",
    ] + cmd[i:]


async def image_present(image: str, run: RunFn) -> bool:
    try:
        await run(["docker", "image", "inspect", image], timeout=INSPECT_TIMEOUT_S)
        return True
    except Exception:
        return False


def _error_text(exc: Exception, job: Job) -> str:
    return redact(str(exc), job.secrets)[:MAX_ERROR_CHARS]


def _first_container_id(out: str) -> str | None:
    """The container id is the first non-empty stdout line; ignore appended stderr."""
    for line in out.splitlines():
        line = line.strip()
        if line:
            return line if _CONTAINER_ID_RE.match(line) else None
    return None


async def launch_detached(
    job: Job,
    cmd: list[str],
    extra_env: dict[str, str] | None,
    store: JobStore,
    run: RunFn,
) -> None:
    try:
        await _launch(job, cmd, extra_env, store, run)
    except asyncio.CancelledError:
        job.error = "launch cancelled"
        job.stage = "failed"
        store.save(job)
        raise


async def _launch(
    job: Job,
    cmd: list[str],
    extra_env: dict[str, str] | None,
    store: JobStore,
    run: RunFn,
) -> None:
    if job.stage == "pulling_image":
        try:
            await run(["docker", "pull", job.image], timeout=PULL_TIMEOUT_S)
        except Exception as exc:
            prefix = "image pull failed: "
            job.error = prefix + redact(str(exc), job.secrets)[: MAX_ERROR_CHARS - len(prefix)]
            job.stage = "failed"
            store.save(job)
            return
    job.stage = "starting"
    store.save(job)
    try:
        out = await run(cmd, timeout=RUN_TIMEOUT_S, extra_env=extra_env)
    except Exception as exc:
        job.error = _error_text(exc, job)
        job.stage = "failed"
        store.save(job)
        return
    job.container_id = _first_container_id(out)
    job.stage = "launched"
    store.save(job)
