import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import detect  # noqa: E402


def _run_with_argv(argv):
    old_argv = sys.argv
    sys.argv = ["detect.py", *argv]
    try:
        return detect.main()
    finally:
        sys.argv = old_argv


def test_no_arguments_exits_zero_and_prints_usage(capsys):
    exit_code = _run_with_argv([])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "usage:" in out
    assert "files" in out
    assert "urls" in out


def test_help_flag_also_works(capsys):
    with pytest.raises(SystemExit) as exc_info:
        _run_with_argv(["--help"])
    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert "usage:" in out
