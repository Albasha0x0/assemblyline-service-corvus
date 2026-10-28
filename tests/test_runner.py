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

