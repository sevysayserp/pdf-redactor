"""Guardrail: no real document, redaction output, or redaction list may ever
be trackable by git. Only the fabricated set under testdata/ is committed."""

import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def check_ignore(path):
    return subprocess.run(
        ["git", "check-ignore", "-q", path], cwd=REPO
    ).returncode == 0


def test_documents_and_lists_are_ignored_everywhere():
    assert check_ignore("statement.pdf")
    assert check_ignore("private/2025/w2.pdf")
    assert check_ignore("private/2025/redacted/w2.txt")
    assert check_ignore("redaction_list.txt")
    assert check_ignore("private/redaction_list.txt")


def test_fake_testdata_is_not_ignored():
    # the global *.pdf and redaction_list.txt rules must not swallow the fakes
    assert not check_ignore("testdata/w2-fake.pdf")
    assert not check_ignore("testdata/redaction_list.txt")


def test_local_redaction_output_in_testdata_is_ignored():
    assert check_ignore("testdata/redacted/w2-fake.txt")
    assert check_ignore("testdata/redacted/w2-fake.redacted.pdf")


def test_no_documents_tracked_outside_testdata():
    out = subprocess.run(
        ["git", "ls-files"], cwd=REPO, capture_output=True, text=True, check=True,
    ).stdout.split()
    bad = [f for f in out
           if (f.endswith(".pdf") or f.endswith("redaction_list.txt"))
           and not f.startswith("testdata/")]
    assert bad == [], f"documents tracked outside testdata/: {bad}"
