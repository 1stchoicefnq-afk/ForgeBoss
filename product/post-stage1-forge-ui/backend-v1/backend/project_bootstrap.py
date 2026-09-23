from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from .project_memory import redact_secrets

BIBLE_FILES = (
    "START_HERE.md",
    "PROJECT_IDEA.md",
    "REQUIREMENTS.md",
    "ARCHITECTURE.md",
    "RULES.md",
    "SAFETY.md",
    "WORKFLOW.md",
    "REVIEW_STANDARD.md",
    "ACCEPTANCE.md",
    "DECISIONS.md",
    "CHANGELOG.md",
)


def _safe_name(name: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._ -]+", "-", str(name or "").strip()).strip(" .-")
    return value or "ForgeBoss-Project"


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_new(path: Path, text: str) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite existing project file: {path}")
    path.write_text(text, encoding="utf-8", newline="\n")


def create_project_scaffold(parent: str | Path, name: str, idea: str, answers: dict[str, str] | None = None) -> Path:
    parent = Path(parent).resolve()
    project = parent / _safe_name(name)
    if project.exists():
        raise FileExistsError(f"project already exists: {project}")
    bible = project / ".forgeboss" / "bible"
    for d in (bible, project/".forgeboss"/"memory", project/".forgeboss"/"evidence", project/".forgeboss"/"runs"):
        d.mkdir(parents=True, exist_ok=False if d == bible else True)

    idea = str(idea or "").strip()
    if not idea:
        raise ValueError("project idea must not be empty")
    safe_idea, idea_redacted = redact_secrets(idea)
    if idea_redacted:
        raise ValueError("project idea contained secret material; store credentials in Forge Vault instead")
    answers = {str(k): str(v) for k,v in (answers or {}).items()}
    safe_answers = {}
    for key, value in answers.items():
        safe_value, was_redacted = redact_secrets(value)
        if was_redacted:
            raise ValueError(f"intake answer {key!r} contained secret material; store credentials in Forge Vault instead")
        safe_answers[key] = safe_value
    answers = safe_answers
    created = datetime.now(timezone.utc).isoformat()

    content = {
        "START_HERE.md": f"# {name}\n\nStatus: FOUNDATION_DRAFT\n\nCreated: {created}\n\nStart with PROJECT_IDEA.md, REQUIREMENTS.md and SAFETY.md.\n",
        "PROJECT_IDEA.md": f"# Project Idea\n\n{safe_idea}\n",
        "REQUIREMENTS.md": "# Requirements\n\nInitial requirements are derived from the approved intake answers and must be made explicit before autonomous implementation.\n\n" + "\n".join(f"- **{k}:** {v}" for k,v in answers.items()) + "\n",
        "ARCHITECTURE.md": "# Architecture\n\nTo be engineered and reviewed from the approved requirements before implementation.\n",
        "RULES.md": "# Rules\n\n- The Project Bible is authoritative.\n- Do not silently change owner-approved requirements.\n- Prefer bounded, reversible changes.\n",
        "SAFETY.md": "# Safety\n\n- Risky/destructive actions require explicit authority.\n- Secrets never belong in the Bible, chat exports, Git, logs or evidence bundles.\n- Budget and STOP gates fail closed.\n",
        "WORKFLOW.md": "# Workflow\n\nPLAN -> FORGE -> TEMPER -> INSPECT -> PROVE\n\nOnly decision-grade blockers should interrupt autonomous work.\n",
        "REVIEW_STANDARD.md": "# Review Standard\n\nTreat green tests as provisional. Attack adjacent paths, bypasses, stale entrypoints, authority boundaries and platform-specific behavior.\n",
        "ACCEPTANCE.md": "# Acceptance\n\nAcceptance criteria are derived from explicit requirements and must be executable where practical.\n",
        "DECISIONS.md": "# Decisions\n\nOwner-approved or otherwise explicitly validated project decisions are recorded here.\n",
        "CHANGELOG.md": f"# Changelog\n\n- {created}: initial ForgeBoss project foundation created from project intake.\n",
    }
    for filename in BIBLE_FILES:
        _write_new(bible/filename, content[filename])

    manifest = {
        "schema": 1,
        "created_at": created,
        "state": "FOUNDATION_DRAFT",
        "files": {f: _hash(bible/f) for f in BIBLE_FILES},
    }
    _write_new(project/".forgeboss"/"BIBLE-MANIFEST.json", json.dumps(manifest, indent=2) + "\n")
    return project
