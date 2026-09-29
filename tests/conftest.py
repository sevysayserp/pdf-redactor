"""Guardrail: the suite must never load the real master redaction list.

redact.py looks it up under XDG_CONFIG_HOME, so every test (and every script
subprocess, which inherits the environment) gets an empty config directory.
"""

import pytest


@pytest.fixture(autouse=True)
def isolated_config(tmp_path_factory, monkeypatch):
    config = tmp_path_factory.mktemp("config")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config))
    return config
