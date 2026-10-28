import pytest

from corvus_service import runner


@pytest.mark.parametrize("timeout,limit", [(300, 255), (60, 30), (20, 10), (3600, 3555)])
def test_the_time_limit_leaves_the_service_time_to_report(timeout, limit):
    assert runner.time_limit(timeout) == limit


@pytest.mark.parametrize("timeout", [300, 60, 20, 3600])
def test_corvus_is_killed_after_its_own_limit_and_before_the_service_timeout(timeout):
    limit, kill = runner.time_limit(timeout), runner.kill_after(runner.time_limit(timeout), timeout)
    assert limit < kill <= timeout - runner.STOP_MARGIN_SECONDS


def test_the_kill_time_is_the_limit_plus_grace_when_the_timeout_allows_it():
    assert runner.kill_after(255, 300) == 255 + runner.GRACE_SECONDS
    assert runner.kill_after(10, 20) == 15


def test_the_command_reads_one_file_with_the_configured_limits():
    assert runner.command("/tmp/f", 255, container_files=7, strings=8, corvus="corvus") == [
        "corvus", "batch", "--file", "/tmp/f", "--json", "--no-index", "--time-limit", "255",
        "--limit", "containerFiles=7", "--limit", "strings=8",
    ]



def test_the_steps_share_the_time_left_before_the_reserve():
    assert runner.steps_budget(300, 30.5, 2) == (119, 254)
    assert runner.steps_budget(300, 0, 1) == (270, 285)


def test_no_steps_run_when_less_than_the_minimum_is_left():
    assert runner.steps_budget(300, 265, 2) is None
    assert runner.steps_budget(300, 0, 0) is None


def test_the_steps_command_runs_one_session_with_a_call_timeout():
    assert runner.steps_command("/tmp/s.jsonl", 60, corvus="corvus") == [
        "corvus", "batch", "/tmp/s.jsonl", "--json", "--no-index", "--timeout", "60"]


def test_a_script_without_its_extension_is_read_through_a_link_that_has_it(tmp_path):
    script = tmp_path / "1512fcc7"
    script.write_text("console.log(1);\n")
    linked = runner.named(str(script), "code/javascript", str(tmp_path))
    assert linked == str(tmp_path / "1512fcc7.js")
    with open(linked, encoding="utf-8") as f:
        assert f.read() == "console.log(1);\n"


def test_a_name_with_its_extension_or_another_type_is_kept(tmp_path):
    assert runner.named("/tmp/app.mjs", "code/javascript", str(tmp_path)) == "/tmp/app.mjs"
    assert runner.named("/tmp/1512fcc7", "archive/ar", str(tmp_path)) == "/tmp/1512fcc7"
