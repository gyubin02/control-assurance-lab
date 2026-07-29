from __future__ import annotations

import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "checks.yml"
LOCK = PROJECT_ROOT / "requirements" / "ci.lock"

ACTION_USE = re.compile(r"^\s*-\s+uses:\s+([^@\s]+)@([^\s#]+)", re.MULTILINE)
FULL_COMMIT = re.compile(r"^[0-9a-f]{40}$")


def test_third_party_actions_are_pinned_to_full_commits() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    actions = ACTION_USE.findall(workflow)

    assert actions
    assert all(FULL_COMMIT.fullmatch(revision) for _, revision in actions)


def test_ci_installs_only_hash_locked_python_dependencies() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    lock = LOCK.read_text(encoding="utf-8")

    assert (
        "pip install --only-binary=:all: --require-hashes -r requirements/ci.lock"
        in workflow
    )
    assert "pip install --no-deps --no-build-isolation ." in workflow
    assert "--hash=sha256:" in lock


def test_checkout_does_not_persist_a_writeable_git_credential() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "persist-credentials: false" in workflow
