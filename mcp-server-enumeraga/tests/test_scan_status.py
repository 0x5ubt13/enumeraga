import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from mcp_server_enumeraga.scan_status import (
    ContainerInfo,
    LogProgress,
    build_status,
    derive_stage,
    format_duration,
    parse_log_progress,
    parse_ts,
    read_closing_run_line,
    read_progress,
    redact,
    strip_ansi,
)

FIXTURE = Path(__file__).parent / "fixtures" / "infra_scan_ansi.log"
UTC = timezone.utc


def fixture_lines():
    return FIXTURE.read_text().splitlines()


def test_strip_ansi_removes_colour_codes():
    assert strip_ansi("\x1b[31mred\x1b[0m plain") == "red plain"


def test_parse_log_progress_from_fixture():
    lines = fixture_lines()
    lp = parse_log_progress(lines)
    assert lp.percent == 70
    assert lp.total == 20
    assert lp.running is None
    assert lp.running_count == 12

    cut = next(i for i, ln in enumerate(lines) if "[70%]" in ln)
    lp = parse_log_progress(lines[:cut])
    assert lp.percent == 65
    assert lp.running == ["ffuf on port 8080", "nikto on port 443"]
    assert lp.running_count is None


def test_parse_log_progress_nothing_found_returns_nones():
    lp = parse_log_progress(["hello", "world"])
    assert lp == LogProgress(None, None, None, None)


@pytest.mark.parametrize(
    "text",
    ["2026-11-04T10:12:31.123456789Z", "2026-11-04T10:12:31Z", "2026-11-04T10:12:31.5Z"],
)
def test_parse_ts_accepts_go_nanoseconds_and_z(text):
    ts = parse_ts(text)
    assert ts.tzinfo is not None
    assert ts.utcoffset() == timedelta(0)
    assert ts.replace(microsecond=0) == datetime(2026, 11, 4, 10, 12, 31, tzinfo=UTC)
    if "123456789" in text:
        assert ts.microsecond == 123456


def write_progress(d, **over):
    data = {
        "schema": 1, "kind": "infra", "target": "10.0.0.5",
        "started_at": "2026-11-04T10:00:00Z", "updated_at": "2026-11-04T10:05:00Z",
        "phase": "running", "completed": 13, "failed": 1, "skipped": 2, "total": 20,
        "total_is_provisional": True, "running": ["nikto on port 443"],
        "max_runtime_s": 3600, "deadline_exceeded": False, "process_exit_code": None,
    }
    data.update(over)
    (d / "progress.json").write_text(json.dumps(data))


NOT_BEFORE = datetime(2026, 11, 4, 10, 0, 0, tzinfo=UTC)


def test_read_progress_matching_file(tmp_path):
    write_progress(tmp_path)
    got = read_progress(tmp_path, kind="infra", target="10.0.0.5", not_before=NOT_BEFORE)
    assert got["completed"] == 13
    assert read_progress(tmp_path, kind=None, target=None, not_before=None) is not None


def test_read_progress_missing_file(tmp_path):
    assert read_progress(tmp_path, kind=None, target=None, not_before=None) is None


@pytest.mark.parametrize(
    "over,raw",
    [
        ({"kind": "cloud"}, None),
        ({"target": "10.9.9.9"}, None),
        ({"started_at": "2026-11-04T09:00:00Z"}, None),
        ({"schema": 2}, None),
        ({}, '{"schema": 1, "kind": "inf'),
    ],
)
def test_read_progress_rejects_other_scan(tmp_path, over, raw):
    write_progress(tmp_path, **over)
    if raw is not None:
        (tmp_path / "progress.json").write_text(raw)
    got = read_progress(tmp_path, kind="infra", target="10.0.0.5", not_before=NOT_BEFORE)
    assert got is None


def test_read_progress_tolerates_five_seconds_of_skew(tmp_path):
    write_progress(tmp_path, started_at="2026-11-04T09:59:56Z")
    assert read_progress(tmp_path, kind=None, target=None, not_before=NOT_BEFORE) is not None


def closing(target, ended="2026-11-04T10:41:03.123456789Z", code=0):
    d = {"kind": "run", "argv": None, "ended_at": ended,
         "deadline_exceeded": False, "process_exit_code": code}
    if target is not None:
        d["target"] = target
    return json.dumps(d)


def test_closing_line_ignores_other_target(tmp_path):
    opening = json.dumps({"kind": "run", "argv": ["x"], "started_at": "2026-11-04T10:00:00Z"})
    tool = json.dumps({"kind": "tool", "name": "nmap"})
    lines = [opening, closing("10.0.0.5", code=0), tool, closing("10.0.0.6", code=2)]
    (tmp_path / "run.jsonl").write_text("\n".join(lines) + "\n")
    a = read_closing_run_line(tmp_path, target="10.0.0.5", not_before=NOT_BEFORE)
    b = read_closing_run_line(tmp_path, target="10.0.0.6", not_before=NOT_BEFORE)
    assert a["process_exit_code"] == 0
    assert b["process_exit_code"] == 2
    assert read_closing_run_line(tmp_path, target="10.0.0.7", not_before=NOT_BEFORE) is None

    (tmp_path / "run.jsonl").write_text(closing(None, code=124) + "\n")
    got = read_closing_run_line(tmp_path, target="10.0.0.7", not_before=NOT_BEFORE)
    assert got["process_exit_code"] == 124


def test_closing_line_before_not_before_is_ignored(tmp_path):
    (tmp_path / "run.jsonl").write_text(closing("10.0.0.5", ended="2026-11-04T09:00:00Z") + "\n")
    assert read_closing_run_line(tmp_path, target="10.0.0.5", not_before=NOT_BEFORE) is None


def test_closing_line_reads_only_tail_and_survives_partial_first_line(tmp_path):
    filler = json.dumps({"kind": "tool", "pad": "x" * 200})
    body = "\n".join([filler] * 600 + [closing("10.0.0.5")]) + "\n"
    assert len(body) > 64 * 1024
    (tmp_path / "run.jsonl").write_text(body)
    got = read_closing_run_line(tmp_path, target="10.0.0.5", not_before=None)
    assert got is not None


def c(state, code=None):
    return ContainerInfo("abc", "enumeraga-x", state, code)


def prog(**over):
    d = {"phase": "running", "completed": 1, "total": 2}
    d.update(over)
    return d


def clos(code=0, deadline=False):
    return {"kind": "run", "ended_at": "2026-11-04T10:41:03Z",
            "process_exit_code": code, "deadline_exceeded": deadline}


@pytest.mark.parametrize(
    "args,expected",
    [
        # 1
        (dict(job_stage="failed", container=c("running")), "failed"),
        # 2
        (dict(job_stage="pulling_image", job_orphaned=True), "failed"),
        (dict(job_stage="starting", job_orphaned=True, container_known=True), "failed"),
        # 3
        (dict(job_stage="pulling_image"), "pulling_image"),
        # 4
        (dict(job_stage="starting"), "starting"),
        # 5
        (dict(job_stage="launched", container=c("created")), "starting"),
        # 6
        (dict(job_stage="launched", container=c("running")), "running"),
        (dict(job_stage="launched", container=c("restarting")), "running"),
        (dict(job_stage="launched", container=c("paused")), "running"),
        # 7
        (dict(job_stage="launched", closing=clos(0)), "finished"),
        (dict(job_stage="launched", closing=clos(2)), "failed"),
        # 8
        (dict(job_stage="launched", container=c("exited", 0)), "finished"),
        (dict(job_stage="launched", container=c("dead", 1)), "failed"),
        # 9
        (dict(job_stage="launched", progress=prog(phase="finished")), "finished"),
        (dict(job_stage="launched", progress=prog(phase="failed")), "failed"),
        # 10
        (dict(job_stage="launched", progress=prog(), container_known=True), "failed"),
        # 11
        (dict(job_stage=None, progress=prog(), container_known=False), "running"),
        # 12
        (dict(job_stage="launched", container_known=True), "failed"),
        # 13
        (dict(job_stage=None), "not_found"),
    ],
)
def test_derive_stage_table(args, expected):
    base = dict(job_stage=None, job_orphaned=False, container=None,
                container_known=False, progress=None, closing=None)
    base.update(args)
    stage, _ = derive_stage(**base)
    assert stage == expected


def test_derive_stage_reasons():
    base = dict(job_stage=None, job_orphaned=False, container=None,
                container_known=False, progress=None, closing=None)
    stage, reason = derive_stage(
        **{**base, "job_stage": "starting", "job_orphaned": True, "container_known": True})
    assert reason == "the MCP server stopped before the scan was started"

    stage, reason = derive_stage(**{**base, "closing": clos(124, deadline=True)})
    assert stage == "finished"
    assert reason == "stopped at its wall-clock limit; results are partial but valid"

    stage, reason = derive_stage(**{**base, "container": c("exited", 3)})
    assert (stage, reason) == ("failed", "exited with code 3")

    stage, reason = derive_stage(**{**base, "progress": prog(), "container_known": True})
    assert reason == "the container exited without completing its record"

    stage, reason = derive_stage(**{**base, "progress": prog()})
    assert reason == "container state unknown: no job record for this directory"


DOCKER_UNKNOWN_REASON = "container state unknown: docker did not answer; poll again"


@pytest.mark.parametrize(
    "args,expected",
    [
        # 10 with a job but the container state unknown: absence is not evidence
        (dict(job_stage="launched", progress=prog()), ("running", DOCKER_UNKNOWN_REASON)),
        # 12 with the container state unknown
        (dict(job_stage="launched"), ("running", DOCKER_UNKNOWN_REASON)),
        # 7 and 9 are real evidence and still win
        (dict(job_stage="launched", progress=prog(), closing=clos(0)), ("finished", None)),
        (dict(job_stage="launched", closing=clos(2)), ("failed", "exited with code 2")),
        (dict(job_stage="launched", progress=prog(phase="finished")), ("finished", None)),
    ],
)
def test_derive_stage_with_container_state_unknown(args, expected):
    base = dict(job_stage=None, job_orphaned=False, container=None,
                container_known=False, progress=None, closing=None)
    base.update(args)
    assert derive_stage(**base) == expected


def test_format_duration():
    assert format_duration(41) == "41s"
    assert format_duration(751) == "12m31s"
    assert format_duration(3725) == "1h02m05s"


def build(**over):
    kw = dict(
        scan_id="enum-1", stage="running", reason=None,
        progress={
            "started_at": "2026-11-04T10:00:00Z", "updated_at": "2026-11-04T10:12:31Z",
            "phase": "running", "completed": 13, "failed": 1, "skipped": 2, "total": 20,
            "total_is_provisional": True,
            "running": ["nikto on port 443", "ffuf on port 8080"],
            "max_runtime_s": 3600, "deadline_exceeded": False,
        },
        log_progress=None, closing=None, container=c("running"),
        results_path="/host/out", job_created_at=datetime(2026, 11, 4, 9, 59, 0, tzinfo=UTC),
        last_log_lines=["a"], now=datetime(2026, 11, 4, 10, 12, 31, tzinfo=UTC),
    )
    kw.update(over)
    return build_status(**kw)


def test_build_status_shape():
    out = build()
    assert set(out) == {
        "scan_id", "stage", "summary", "progress", "elapsed_s", "max_runtime_s",
        "deadline_exceeded", "container", "results_path", "run_record",
        "progress_source", "last_log_lines",
    }
    assert out["progress"]["percent"] == 65
    assert out["progress_source"] == "progress.json"
    assert out["elapsed_s"] == 751
    assert out["summary"] == (
        "65% (13/20, provisional): running nikto on port 443, ffuf on port 8080; 12m31s elapsed"
    )
    assert out["container"] == {"id": "abc", "name": "enumeraga-x", "state": "running", "exit_code": None}
    assert out["run_record"] == "/host/out/run.jsonl"
    assert set(out["progress"]) == {
        "completed", "total", "percent", "total_is_provisional", "failed", "skipped", "running",
    }


def test_build_status_summary_variants():
    raw = {
        "started_at": "2026-11-04T10:00:00Z", "updated_at": "2026-11-04T10:41:03Z",
        "phase": "finished", "completed": 20, "failed": 1, "skipped": 2, "total": 20,
        "total_is_provisional": False, "running": [],
        "max_runtime_s": None, "deadline_exceeded": False,
    }
    out = build(stage="finished", progress=raw, container=None,
                now=datetime(2026, 11, 4, 12, 0, 0, tzinfo=UTC))
    assert out["summary"] == "finished: 20/20 tools (1 failed, 2 skipped) in 41m03s"
    assert out["elapsed_s"] == 2463

    out = build(stage="failed", reason="boom", progress=None, container=None)
    assert out["summary"] == "failed: boom"

    many = dict(raw, phase="running", completed=5, total_is_provisional=False,
                running=["a", "b", "c", "d", "e"])
    out = build(progress=many)
    assert out["summary"].startswith("25% (5/20): running a, b, c and 2 more; ")

    disc = dict(raw, phase="discovery", completed=0, total=0, running=[],
                started_at="2026-11-04T10:11:26Z")
    out = build(progress=disc)
    assert out["summary"] == "discovering ports; 1m05s elapsed"
    assert out["progress"]["percent"] is None

    out = build(stage="pulling_image", reason="gagarter/enumeraga_infra", progress=None,
                container=None)
    assert out["summary"].startswith("pulling image gagarter/enumeraga_infra; ")
    assert out["elapsed_s"] == 811


def test_build_status_falls_back_to_logs():
    lp = LogProgress(percent=70, total=20, running=None, running_count=12)
    out = build(progress=None, log_progress=lp)
    assert out["progress_source"] == "logs"
    assert out["progress"]["percent"] == 70
    assert out["progress"]["completed"] is None
    assert out["progress"]["total"] == 20


def test_build_status_no_evidence():
    out = build(stage="not_found", progress=None, container=None, results_path=None,
                job_created_at=None)
    assert out["progress_source"] is None
    assert out["container"] is None
    assert out["elapsed_s"] is None
    assert out["run_record"] is None


def test_redact_hides_secret_values_and_assignments():
    line = strip_ansi(fixture_lines()[3])
    assert "s3cr3t-value" not in redact(line, frozenset({"s3cr3t-value"}))
    assert "s3cr3t-value" not in redact(line, frozenset())
    assert redact("my password: hunter2 ok", frozenset()) == "my password=*** ok"
    assert redact("keep this", frozenset({"", "  "})) == "keep this"
    assert redact("x tok123 y", frozenset({"tok123"})) == "x *** y"


def test_last_log_lines_capped_at_five():
    out = build(last_log_lines=[f"l{i}" for i in range(9)])
    assert out["last_log_lines"] == ["l4", "l5", "l6", "l7", "l8"]


@pytest.mark.parametrize("phase,total", [("running", 20), ("discovery", 0)])
def test_running_summary_shows_the_reason(phase, total):
    """A running stage resting on unknown container state must say so, whatever the phase."""
    reason = "container state unknown: docker did not answer; poll again"
    progress = {
        "started_at": "2026-11-04T10:00:00Z", "phase": phase, "completed": 0,
        "total": total, "running": [],
    }
    out = build(reason=reason, progress=progress, container=None)
    assert reason in out["summary"]


STOPPED_BY_SIGNAL = "stopped by a signal; results are partial"


@pytest.mark.parametrize("code", [130, 143])
@pytest.mark.parametrize("evidence", ["closing", "container"])
def test_derive_stage_signal_exit_is_failed(code, evidence):
    """A run stopped by docker stop or Ctrl+C must never read as finished."""
    base = dict(job_stage="launched", job_orphaned=False, container=None,
                container_known=True, progress=prog(phase="failed"), closing=None)
    if evidence == "closing":
        base["closing"] = clos(code)
    else:
        base["container"] = c("exited", code)
    assert derive_stage(**base) == ("failed", STOPPED_BY_SIGNAL)


ORPHAN_REASON = "the MCP server stopped before the scan was started"


@pytest.mark.parametrize(
    "args,expected",
    [
        # The container is the evidence: the server may have died after docker run.
        (dict(container=c("running"), container_known=True), ("running", None)),
        (dict(container=c("created"), container_known=True), ("starting", None)),
        (dict(container=c("exited", 0), container_known=True,
              closing=clos(0)), ("finished", None)),
        (dict(container=c("exited", 130), container_known=True), ("failed", STOPPED_BY_SIGNAL)),
        # Only docker's confirmed answer that it is absent makes it a failure.
        (dict(container=None, container_known=True), ("failed", ORPHAN_REASON)),
        (dict(container=None, container_known=False), ("starting", DOCKER_UNKNOWN_REASON)),
    ],
)
def test_derive_stage_orphaned_starting_checks_container_first(args, expected):
    base = dict(job_stage="starting", job_orphaned=True, container=None,
                container_known=False, progress=None, closing=None)
    base.update(args)
    assert derive_stage(**base) == expected


@pytest.mark.parametrize("container_known", [True, False])
def test_derive_stage_orphaned_pull_is_failed_whatever_docker_says(container_known):
    base = dict(job_stage="pulling_image", job_orphaned=True, container=None,
                container_known=container_known, progress=None, closing=None)
    assert derive_stage(**base) == ("failed", ORPHAN_REASON)


def test_logs_fallback_percentage_is_marked_provisional():
    lp = LogProgress(percent=40, total=20, running=["nikto on port 443"], running_count=None)
    out = build(progress=None, log_progress=lp)
    assert out["progress_source"] == "logs"
    assert out["summary"].startswith("40% (from logs; total may grow): running nikto on port 443")


def test_progress_json_percentage_is_not_marked_from_logs():
    assert "from logs" not in build()["summary"]
