import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from miner import (
    detect_done_without_verification,
    detect_file_thrash,
    detect_retry_loop,
    estimate_cost,
    normalize_command,
)


def _bash(cmd, out=""):
    return {"tool": "bash", "command": cmd, "file": "", "output": out}


def _edit(f):
    return {"tool": "edit", "command": "", "file": f, "output": ""}


def test_normalize_strips_volatile():
    a = normalize_command("pytest -x -q 12 --port :3001 /tmp/abc12345")
    b = normalize_command("pytest -x -q 99 --port :3002 /tmp/def67890")
    assert a == b
    assert "<n>" in a and "<port>" in a


def test_retry_loop_fires_on_third_repeat():
    turns = [_bash("npm test 12"), _bash("ls"), _bash("npm test 34"),
             _bash("ls"), _bash("npm test 56")]
    found = detect_retry_loop(turns, "proj", window=30, threshold=3)
    assert len(found) == 1
    assert found[0]["kind"] == "retry_loop"


def test_retry_loop_no_false_positive():
    turns = [_bash("npm test"), _bash("go test ./..."), _bash("pytest -q")]
    assert detect_retry_loop(turns, "proj") == []


def test_file_thrash_threshold():
    turns = [_edit("a.py")] * 4
    found = detect_file_thrash(turns, "proj", threshold=4)
    assert len(found) == 1
    assert found[0]["count"] == 4


def test_done_without_verification():
    assert len(detect_done_without_verification([_edit("a.py")], "p")) == 1
    assert detect_done_without_verification(
        [_edit("a.py"), _bash("pytest -q")], "p") == []


def test_docs_only_needs_no_verification():
    assert detect_done_without_verification([_edit("notes.md")], "p") == []


def test_unknown_model_cost_is_none():
    assert estimate_cost("mystery-model-9", 1000, 1000) is None
