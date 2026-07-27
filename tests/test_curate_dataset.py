"""The dataset curator produces valid, labeled, balanced training examples.

This is the one training-pipeline piece that runs without GPU/ML deps, so it is
covered in CI. The GPU scripts (train/eval/iterate/export) are only compile-checked.
"""
import json

from ml.curate_dataset import build

CLEAN_SOURCE = '''\
def total(items):
    result = 0
    for i in range(len(items)):
        if items[i] is not None:
            result = result + items[i]
    return result


def safe_div(a, b):
    try:
        return a / b
    except ZeroDivisionError:
        return 0
'''


def test_build_produces_labeled_positives_and_negatives(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "mod.py").write_text(CLEAN_SOURCE, encoding="utf-8")
    out = tmp_path / "data"

    stats = build(src, out, max_examples=100, seed=0)

    assert stats["positives"] > 0  # bugs were injected
    assert stats["negatives"] > 0  # clean negatives kept
    assert (out / "train.jsonl").exists()
    assert (out / "val.jsonl").exists()


def test_examples_are_well_formed_and_targets_parse(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "mod.py").write_text(CLEAN_SOURCE, encoding="utf-8")
    out = tmp_path / "data"
    build(src, out, max_examples=100, seed=0)

    rows = [
        json.loads(line)
        for line in (out / "train.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert rows
    for r in rows:
        roles = [m["role"] for m in r["messages"]]
        assert roles == ["system", "user", "assistant"]
        # The assistant target is always valid JSON with an "issues" list.
        target = json.loads(r["messages"][-1]["content"])
        assert isinstance(target["issues"], list)
        if r["meta"]["label"] == "clean":
            assert target["issues"] == []
        else:
            assert len(target["issues"]) == 1
            assert target["issues"][0]["line_start"] >= 1


def test_buggy_example_line_points_at_a_real_line(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "mod.py").write_text(CLEAN_SOURCE, encoding="utf-8")
    out = tmp_path / "data"
    build(src, out, max_examples=100, seed=0)

    rows = [
        json.loads(line)
        for line in (out / "train.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    buggy = [r for r in rows if r["meta"]["label"] == "buggy"]
    assert buggy
    for r in buggy:
        # The labeled line exists in the user-message source rendering.
        line = json.loads(r["messages"][-1]["content"])["issues"][0]["line_start"]
        user = r["messages"][1]["content"]
        assert f"{line:>5} +" in user
