"""Pure functions that work out a scan's stage and progress.

Nothing here starts, stops or retries anything, and nothing talks to Docker:
callers pass in what they have found (job record, container state, files) and
get back a small status object.
"""

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PROGRESS_FILE = "progress.json"
RUN_RECORD_FILE = "run.jsonl"
RUN_TAIL_BYTES = 64 * 1024
CLOCK_SKEW_S = 5
MAX_LOG_LINES = 5
MAX_SHOWN_RUNNING = 3

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_STILL_RE = re.compile(r"\[(\d{1,3})%\]\s*Still running:\s*(.*)")
_COUNT_RE = re.compile(r"^(\d+) tools?$")
_TOTAL_RE = re.compile(r"\[!\]\s*Running '.*?'\s*\((\d+) tools? total,\s*(\d+) running\)")
_SECRET_RE = re.compile(
    r"(?i)\b([A-Z0-9_]*(SECRET|PASSWORD|TOKEN|KEY)[A-Z0-9_]*)\s*[=:]\s*\S+"
)
_FRACTION_RE = re.compile(r"\.(\d+)")


def strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s)


def parse_ts(s: str) -> datetime:
    """Parse an RFC3339 time as written by the Go side, as an aware UTC datetime.

    Normalised by hand because datetime.fromisoformat rejects 'Z' and more than
    six fractional digits before Python 3.11.
    """
    s = s.strip()
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    s = _FRACTION_RE.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), s, count=1)
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _to_dt(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        return parse_ts(str(value))
    except ValueError:
        return None


@dataclass
class LogProgress:
    percent: int | None
    total: int | None
    running: list[str] | None
    running_count: int | None


def parse_log_progress(lines: list[str]) -> LogProgress:
    percent = total = running_count = None
    running = None
    for raw in lines:
        line = strip_ansi(raw)
        m = _STILL_RE.search(line)
        if m:
            percent = int(m.group(1))
            rest = m.group(2).strip()
            count = _COUNT_RE.match(rest)
            if count:
                running, running_count = None, int(count.group(1))
            else:
                running = [t.strip() for t in rest.split(",") if t.strip()]
                running_count = None
        m = _TOTAL_RE.search(line)
        if m:
            total = int(m.group(1))
    return LogProgress(percent, total, running, running_count)


def read_progress(
    output_dir: Path, *, kind: str | None, target: str | None, not_before: datetime | None
) -> dict | None:
    try:
        data = json.loads((Path(output_dir) / PROGRESS_FILE).read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("schema") != 1:
        return None
    if kind is not None and data.get("kind") != kind:
        return None
    if target is not None and data.get("target") != target:
        return None
    if not_before is not None:
        started = _to_dt(data.get("started_at"))
        if started is None:
            return None
        if (not_before - started).total_seconds() > CLOCK_SKEW_S:
            return None
    return data


def read_closing_run_line(
    output_dir: Path, *, target: str | None, not_before: datetime | None
) -> dict | None:
    path = Path(output_dir) / RUN_RECORD_FILE
    try:
        with open(path, "rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - RUN_TAIL_BYTES))
            raw = fh.read()
            truncated = size > RUN_TAIL_BYTES
    except OSError:
        return None
    lines = raw.decode("utf-8", errors="replace").splitlines()
    if truncated and lines:
        lines = lines[1:]  # the first line is probably cut in half
    for line in reversed(lines):
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if not isinstance(obj, dict) or obj.get("kind") != "run" or not obj.get("ended_at"):
            continue
        if "target" in obj and obj["target"] is not None and target is not None:
            if obj["target"] != target:
                continue
        if not_before is not None:
            ended = _to_dt(obj["ended_at"])
            if ended is None or ended < not_before:
                continue
        return obj
    return None


# Exit codes of a run stopped by a signal: 130 is enumeraga's own code for an
# interrupted run (128 + SIGINT); 143 is 128 + SIGTERM, which docker reports when
# the process died of the signal before it could record anything.
SIGNAL_EXIT_CODES = (130, 143)


@dataclass
class ContainerInfo:
    id: str
    name: str
    state: str
    exit_code: int | None


def derive_stage(
    job_stage: str | None,
    job_orphaned: bool,
    container: ContainerInfo | None,
    container_known: bool,
    progress: dict | None,
    closing: dict | None,
) -> tuple[str, str | None]:
    """Work out the stage from what was found; the first matching rule wins.

    container_known is False when the container's state could not be established.
    With no job record (job_stage None) that is because there is no container name
    to look for; with a job record it is because docker did not answer. Either way
    the container's absence is not evidence, so only a closing run line or a
    terminal phase in progress.json can make the stage terminal.
    """
    no_record = "the container exited without completing its record"
    docker_unknown = "container state unknown: docker did not answer; poll again"
    stopped_by_signal = "stopped by a signal; results are partial"
    if job_stage == "failed":
        return "failed", "job error"
    never_started = "the MCP server stopped before the scan was started"
    if job_stage == "pulling_image" and job_orphaned:
        # No container can exist before the pull has finished.
        return "failed", never_started
    if job_stage == "pulling_image":
        return "pulling_image", None
    if job_stage == "starting" and job_orphaned:
        # The server may have stopped after docker run was issued, so the
        # container is the evidence: only its confirmed absence means it never ran.
        if container is None and container_known:
            return "failed", never_started
        if container is None:
            return "starting", docker_unknown
    elif job_stage == "starting":
        return "starting", None
    state = container.state if container else None
    if state == "created":
        return "starting", None
    if state in ("running", "restarting", "paused"):
        return "running", None
    if closing is not None:
        code = closing.get("process_exit_code")
        if code in SIGNAL_EXIT_CODES:
            return "failed", stopped_by_signal
        stage = "finished" if code in (0, 124) else "failed"
        if closing.get("deadline_exceeded") or code == 124:
            return stage, "stopped at its wall-clock limit; results are partial but valid"
        return stage, None if stage == "finished" else f"exited with code {code}"
    if state in ("exited", "dead"):
        code = container.exit_code
        if code in SIGNAL_EXIT_CODES:
            return "failed", stopped_by_signal
        return ("finished" if code in (0, 124) else "failed"), f"exited with code {code}"
    if progress is not None and progress.get("phase") in ("finished", "failed"):
        return progress["phase"], None
    if progress is not None and container_known:
        return "failed", no_record
    if progress is not None and job_stage is not None:
        return "running", docker_unknown
    if progress is not None:
        return "running", "container state unknown: no job record for this directory"
    if job_stage == "launched" and container_known:
        return "failed", no_record
    if job_stage == "launched":
        return "running", docker_unknown
    return "not_found", None


def format_duration(seconds: int) -> str:
    seconds = max(0, int(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h{m:02d}m{s:02d}s"
    if m:
        return f"{m}m{s:02d}s"
    return f"{s}s"


def redact(line: str, secrets: frozenset[str]) -> str:
    for secret in secrets:
        if secret and secret.strip():
            line = line.replace(secret, "***")
    return _SECRET_RE.sub(r"\1=***", line)


def _running_phrase(names: list[str] | None, count: int | None) -> str | None:
    if names:
        shown = ", ".join(names[:MAX_SHOWN_RUNNING])
        if len(names) > MAX_SHOWN_RUNNING:
            shown += f" and {len(names) - MAX_SHOWN_RUNNING} more"
        return f"running {shown}"
    if count:
        return f"running {count} tools"
    return None


def _percent(completed, total) -> int | None:
    if completed is None or not total:
        return None
    return completed * 100 // total


def build_status(
    *,
    scan_id,
    stage,
    reason,
    progress,
    log_progress,
    closing,
    container,
    results_path,
    job_created_at,
    last_log_lines,
    now,
) -> dict:
    logs_have_data = log_progress is not None and any(
        v is not None
        for v in (log_progress.percent, log_progress.total, log_progress.running,
                  log_progress.running_count)
    )
    if progress is not None:
        source = "progress.json"
        completed = progress.get("completed")
        total = progress.get("total")
        info = {
            "completed": completed,
            "total": total,
            "percent": _percent(completed, total),
            "total_is_provisional": progress.get("total_is_provisional"),
            "failed": progress.get("failed"),
            "skipped": progress.get("skipped"),
            "running": list(progress.get("running") or []),
        }
    elif logs_have_data:
        source = "logs"
        info = {
            "completed": None,
            "total": log_progress.total,
            "percent": log_progress.percent,
            "total_is_provisional": None,
            "failed": None,
            "skipped": None,
            "running": log_progress.running,
        }
    else:
        source = None
        info = {
            "completed": None, "total": None, "percent": None,
            "total_is_provisional": None, "failed": None, "skipped": None, "running": None,
        }

    start = _to_dt(progress.get("started_at")) if progress else None
    start = start or _to_dt(job_created_at)
    end = now
    if stage in ("finished", "failed"):
        ended = _to_dt(closing.get("ended_at")) if closing else None
        if ended is None and progress:
            ended = _to_dt(progress.get("updated_at"))
        end = ended or now
    elapsed = max(0, int((end - start).total_seconds())) if start else None

    summary = _summary(stage, reason, progress, info, log_progress, source, elapsed)

    deadline = False
    if closing is not None and closing.get("deadline_exceeded") is not None:
        deadline = bool(closing["deadline_exceeded"])
    elif progress is not None:
        deadline = bool(progress.get("deadline_exceeded"))

    return {
        "scan_id": scan_id,
        "stage": stage,
        "summary": summary,
        "progress": info,
        "elapsed_s": elapsed,
        "max_runtime_s": progress.get("max_runtime_s") if progress else None,
        "deadline_exceeded": deadline,
        "container": (
            {"id": container.id, "name": container.name, "state": container.state,
             "exit_code": container.exit_code}
            if container else None
        ),
        "results_path": results_path,
        "run_record": f"{str(results_path).rstrip('/')}/{RUN_RECORD_FILE}" if results_path else None,
        "progress_source": source,
        "last_log_lines": list(last_log_lines or [])[-MAX_LOG_LINES:],
    }


def _summary(stage, reason, progress, info, log_progress, source, elapsed) -> str:
    took = f"{format_duration(elapsed)} elapsed" if elapsed is not None else None

    def join(*parts):
        return "; ".join(p for p in parts if p)

    if stage == "failed":
        return f"failed: {reason}" if reason else "failed"
    if stage == "finished":
        if progress is not None:
            text = (
                f"finished: {info['completed']}/{info['total']} tools "
                f"({info['failed']} failed, {info['skipped']} skipped)"
            )
            if elapsed is not None:
                text += f" in {format_duration(elapsed)}"
        else:
            text = "finished" + (f" in {format_duration(elapsed)}" if elapsed is not None else "")
        return join(text, reason)
    if stage == "pulling_image":
        return join(f"pulling image {reason}" if reason else "pulling image", took)
    if stage == "starting":
        return join("starting", took)
    if stage == "not_found":
        return reason or "no scan found"

    # running
    if source == "progress.json":
        total = info["total"]
        if progress.get("phase") == "discovery" and not total:
            return join("discovering ports", reason, took)
        if total:
            prov = ", provisional" if info["total_is_provisional"] else ""
            head = f"{info['percent']}% ({info['completed']}/{total}{prov})"
            run = _running_phrase(info["running"], None)
            return join(f"{head}: {run}" if run else head, reason, took)
    elif source == "logs":
        # The log only shows the tools launched so far, so the total can still grow.
        head = (
            f"{info['percent']}% (from logs; total may grow)"
            if info["percent"] is not None else "running"
        )
        run = _running_phrase(log_progress.running, log_progress.running_count)
        if info["percent"] is not None:
            head = f"{head}: {run}" if run else head
        elif run:
            head = run
        return join(head, took)
    return join("running", reason, took)
