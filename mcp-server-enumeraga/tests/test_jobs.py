import asyncio
import json

import pytest

from mcp_server_enumeraga import jobs
from mcp_server_enumeraga.jobs import Job, JobStore


def make_job(tmp_path, stage="pulling_image", secrets=frozenset(), key="infra:10.0.0.1"):
    return Job(
        scan_id="enum-0000000000ab",
        kind="infra",
        key=key,
        target="10.0.0.1",
        image="img:latest",
        output_dir=str(tmp_path),
        stage=stage,
        created_at="2026-11-05T10:00:00+00:00",
        container_name="enumeraga-enum-0000000000ab",
        secrets=secrets,
    )


class FakeRun:
    def __init__(self, results=None):
        self.calls = []
        self.results = results or {}

    async def __call__(self, cmd, timeout=3600, extra_env=None):
        self.calls.append((list(cmd), timeout, extra_env))
        for prefix, result in self.results.items():
            if cmd[1:3] == prefix.split():
                if isinstance(result, BaseException):
                    raise result
                return result
        return "abc123def456\n"


def read_file(tmp_path):
    return json.loads((tmp_path / jobs.JOB_FILE).read_text())


def test_new_scan_id_format():
    sid = jobs.new_scan_id()
    assert sid.startswith("enum-") and len(sid) == 17


def test_detach_args_inserts_after_run():
    out = jobs.detach_args(["docker", "run", "--rm", "img"], "enum-1")
    assert out == [
        "docker", "run", "-d", "--name", "enumeraga-enum-1",
        "--label", "enumeraga.scan_id=enum-1", "--rm", "img",
    ]


def test_job_file_never_contains_secrets(tmp_path):
    job = make_job(tmp_path, secrets=frozenset({"s3cr3t"}))
    JobStore().save(job)
    assert "s3cr3t" not in (tmp_path / jobs.JOB_FILE).read_text()
    assert "s3cr3t" not in repr(job)
    assert "secrets" not in job.to_dict()


def test_secrets_exclude_blank_values(tmp_path):
    job = make_job(tmp_path, secrets=frozenset({"", "  ", "real"}))
    assert job.secrets == frozenset({"real"})


def test_launch_pulls_then_starts(tmp_path):
    job = make_job(tmp_path)
    store = JobStore()
    store.add(job)
    run = FakeRun()
    stages = []
    orig = store.save

    def spy(j):
        stages.append(j.stage)
        orig(j)

    store.save = spy
    asyncio.run(jobs.launch_detached(job, ["docker", "run", "img"], {"A": "b"}, store, run))
    assert stages == ["starting", "launched"]
    assert run.calls[0][0] == ["docker", "pull", "img:latest"]
    assert run.calls[0][1] == 1800
    assert run.calls[1][0] == ["docker", "run", "img"]
    assert run.calls[1][1] == 120
    assert job.container_id == "abc123def456"
    assert read_file(tmp_path)["stage"] == "launched"


def test_launch_skips_pull_when_starting(tmp_path):
    job = make_job(tmp_path, stage="starting")
    run = FakeRun()
    asyncio.run(jobs.launch_detached(job, ["docker", "run", "img"], None, JobStore(), run))
    assert [c[0][1] for c in run.calls] == ["run"]


def test_launch_pull_failure_marks_failed(tmp_path):
    job = make_job(tmp_path, secrets=frozenset({"s3cr3t"}))
    store = JobStore()
    store.add(job)
    run = FakeRun({"pull img:latest": RuntimeError("Command failed\nno such host s3cr3t " + "x" * 600)})
    asyncio.run(jobs.launch_detached(job, ["docker", "run", "img"], None, store, run))
    assert job.stage == "failed"
    assert job.error.startswith("image pull failed: ")
    assert "no such host" in job.error
    assert "s3cr3t" not in job.error
    assert len(job.error) <= 500
    assert store.active_for_key(job.key) is None
    assert read_file(tmp_path)["stage"] == "failed"
    assert len(run.calls) == 1


def test_launch_run_failure_marks_failed(tmp_path):
    job = make_job(tmp_path)
    store = JobStore()
    store.add(job)
    run = FakeRun({"run img": RuntimeError("Command failed\nname in use")})
    asyncio.run(jobs.launch_detached(job, ["docker", "run", "img"], None, store, run))
    assert job.stage == "failed"
    assert "name in use" in job.error
    assert read_file(tmp_path)["stage"] == "failed"


def test_active_for_key_includes_pulling_job(tmp_path):
    store = JobStore()
    job = make_job(tmp_path)
    store.add(job)
    assert store.active_for_key(job.key) is job
    job.stage = "launched"
    assert store.active_for_key(job.key) is None
    assert store.get("enum-0000000000ab") is job
    assert store.get("nope") is None


def test_load_from_dir_marks_orphaned_job_failed(tmp_path):
    JobStore().save(make_job(tmp_path))
    job, orphaned = JobStore().load_from_dir(tmp_path)
    assert job is not None and job.scan_id == "enum-0000000000ab"
    assert orphaned is True


def test_load_from_dir_in_memory_wins(tmp_path):
    store = JobStore()
    job = make_job(tmp_path)
    store.add(job)
    store.save(job)
    job.stage = "launched"
    loaded, orphaned = store.load_from_dir(tmp_path)
    assert loaded is job and orphaned is False


def test_load_from_dir_never_raises(tmp_path):
    store = JobStore()
    assert store.load_from_dir(tmp_path) == (None, False)
    (tmp_path / jobs.JOB_FILE).write_text("{not json")
    assert store.load_from_dir(tmp_path) == (None, False)
    (tmp_path / jobs.JOB_FILE).write_text('{"scan_id": "x"}')
    assert store.load_from_dir(tmp_path) == (None, False)
    assert store.load_from_dir(tmp_path / "missing") == (None, False)


def test_save_failure_is_swallowed(tmp_path, capsys):
    job = make_job(tmp_path)
    job.output_dir = str(tmp_path / "missing" / "dir")
    store = JobStore()
    store.save(job)
    store.save(job)
    assert capsys.readouterr().err.count("could not write") == 1


def test_extra_env_reaches_run_not_argv(tmp_path):
    job = make_job(tmp_path)
    run = FakeRun()
    asyncio.run(
        jobs.launch_detached(
            job, ["docker", "run", "-e", "AZURE_CLIENT_SECRET", "img"],
            {"AZURE_CLIENT_SECRET": "s3cr3t"}, JobStore(), run,
        )
    )
    assert run.calls[1][2] == {"AZURE_CLIENT_SECRET": "s3cr3t"}
    assert all("s3cr3t" not in a for argv, _, _ in run.calls for a in argv)


def test_image_present(tmp_path):
    run = FakeRun()
    assert asyncio.run(jobs.image_present("img", run)) is True
    assert run.calls[0][0] == ["docker", "image", "inspect", "img"]
    assert run.calls[0][1] == 5
    bad = FakeRun({"image inspect": RuntimeError("nope")})
    assert asyncio.run(jobs.image_present("img", bad)) is False


def test_load_from_dir_rejects_wrong_types(tmp_path):
    good = make_job(tmp_path).to_dict()
    for field_name, bad in (("scan_id", {"a": 1}), ("scan_id", ["x"]), ("stage", 5),
                            ("target", None), ("error", 3), ("container_id", [])):
        (tmp_path / jobs.JOB_FILE).write_text(json.dumps({**good, field_name: bad}))
        assert JobStore().load_from_dir(tmp_path) == (None, False), field_name


def test_load_from_dir_unhashable_scan_id_with_populated_store(tmp_path):
    store = JobStore()
    store.add(make_job(tmp_path))
    (tmp_path / jobs.JOB_FILE).write_text(
        json.dumps({**make_job(tmp_path).to_dict(), "scan_id": {"x": 1}})
    )
    assert store.load_from_dir(tmp_path) == (None, False)


def test_load_from_dir_overrides_claimed_output_dir(tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    claimed = {**make_job(tmp_path).to_dict(), "output_dir": "/etc"}
    (other / jobs.JOB_FILE).write_text(json.dumps(claimed))
    job, _ = JobStore().load_from_dir(other)
    assert job.output_dir == str(other)


def test_load_from_dir_ignores_spoofed_scan_id_of_live_job(tmp_path):
    live_dir = tmp_path / "live"
    spoof_dir = tmp_path / "spoof"
    live_dir.mkdir()
    spoof_dir.mkdir()
    store = JobStore()
    live = make_job(live_dir, stage="launched")
    store.add(live)
    (spoof_dir / jobs.JOB_FILE).write_text(json.dumps(make_job(spoof_dir).to_dict()))
    job, orphaned = store.load_from_dir(spoof_dir)
    assert job is not live
    assert job.output_dir == str(spoof_dir)
    assert orphaned is True


def test_container_id_ignores_appended_stderr(tmp_path):
    job = make_job(tmp_path)
    run = FakeRun({"run img": "abc123def456\n\nStderr output:\nWARNING platform mismatch"})
    asyncio.run(jobs.launch_detached(job, ["docker", "run", "img"], None, JobStore(), run))
    assert job.stage == "launched" and job.container_id == "abc123def456"


def test_invalid_container_id_still_launched(tmp_path):
    job = make_job(tmp_path)
    run = FakeRun({"run img": "\nStderr output:\nWARNING"})
    asyncio.run(jobs.launch_detached(job, ["docker", "run", "img"], None, JobStore(), run))
    assert job.stage == "launched" and job.container_id is None


def test_cancelled_launch_marks_failed_and_reraises(tmp_path):
    job = make_job(tmp_path)
    store = JobStore()
    store.add(job)
    run = FakeRun({"pull img:latest": asyncio.CancelledError()})
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(jobs.launch_detached(job, ["docker", "run", "img"], None, store, run))
    assert job.stage == "failed" and job.error == "launch cancelled"
    assert store.active_for_key(job.key) is None
    assert read_file(tmp_path)["stage"] == "failed"
