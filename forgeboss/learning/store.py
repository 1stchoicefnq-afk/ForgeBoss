from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import time
from pathlib import Path

from forgeboss.learning.policy import can_promote
from forgeboss.security.local_acl import harden_private_dir, harden_private_path


class LearningStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        harden_private_dir(self.path.parent)
        self.db = sqlite3.connect(str(self.path), timeout=15)
        self.db.row_factory = sqlite3.Row
        harden_private_path(self.path)
        self.db.executescript(
            """
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS lessons(
          lesson_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
          problem_family TEXT NOT NULL, summary TEXT NOT NULL, repair_pattern_json TEXT NOT NULL,
          evidence_json TEXT NOT NULL, validation_json TEXT NOT NULL, confidence REAL NOT NULL,
          reusable INTEGER NOT NULL, created_at REAL NOT NULL, last_used_at REAL,
          success_count INTEGER NOT NULL DEFAULT 1, failure_count INTEGER NOT NULL DEFAULT 0);
        CREATE INDEX IF NOT EXISTS idx_lessons_lookup ON lessons(project_id,problem_family,fingerprint,reusable,confidence);
        CREATE TABLE IF NOT EXISTS routing_stats(
          project_id TEXT NOT NULL, worker_id TEXT NOT NULL, problem_family TEXT NOT NULL,
          attempts INTEGER NOT NULL DEFAULT 0, successes INTEGER NOT NULL DEFAULT 0,
          total_cost REAL NOT NULL DEFAULT 0, total_latency_ms REAL NOT NULL DEFAULT 0,
          PRIMARY KEY(project_id,worker_id,problem_family));
        """
        )

    @staticmethod
    def fingerprint(problem_family, evidence):
        blob = json.dumps(
            {"family": problem_family, "evidence": evidence},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(blob.encode()).hexdigest()

    def record_verified_lesson(
        self,
        project_id,
        problem_family,
        summary,
        repair_pattern,
        evidence,
        validation,
        confidence=1.0,
        reusable=True,
        *,
        partial_proven=False,
    ):
        if not isinstance(reusable, bool):
            raise ValueError("reusable must be boolean")
        if not isinstance(partial_proven, bool):
            raise ValueError("partial_proven must be boolean")
        try:
            confidence_value = float(confidence)
        except (TypeError, ValueError) as exc:
            raise ValueError("confidence must be a finite value from 0 to 1") from exc
        if not math.isfinite(confidence_value) or confidence_value < 0 or confidence_value > 1:
            raise ValueError("confidence must be a finite value from 0 to 1")

        # The persistence boundary is authoritative for reuse eligibility. Callers may
        # opt out of reuse, but they cannot force unvalidated/regressing evidence into
        # the reusable corpus by passing reusable=True.
        reusable_allowed = reusable and can_promote(validation, partial_proven=partial_proven)

        fp = self.fingerprint(problem_family, evidence)
        lid = hashlib.sha256(f"{project_id}:{problem_family}:{fp}".encode()).hexdigest()
        now = time.time()
        self.db.execute(
            """INSERT INTO lessons(lesson_id,project_id,fingerprint,problem_family,summary,repair_pattern_json,evidence_json,
          validation_json,confidence,reusable,created_at,last_used_at,success_count,failure_count)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1,0)
          ON CONFLICT(lesson_id) DO UPDATE SET summary=excluded.summary,repair_pattern_json=excluded.repair_pattern_json,
          validation_json=excluded.validation_json,confidence=MAX(lessons.confidence,excluded.confidence),
          reusable=excluded.reusable,success_count=lessons.success_count+1,last_used_at=excluded.created_at""",
            (
                lid,
                project_id,
                fp,
                problem_family,
                summary,
                json.dumps(repair_pattern),
                json.dumps(evidence),
                json.dumps(validation),
                confidence_value,
                1 if reusable_allowed else 0,
                now,
                now,
            ),
        )
        self.db.commit()
        return lid

    def find_reusable(self, project_id, problem_family, min_confidence=.85, limit=5):
        rows = self.db.execute(
            """SELECT * FROM lessons WHERE project_id=? AND problem_family=? AND reusable=1
          AND confidence>=? ORDER BY confidence DESC,success_count DESC,last_used_at DESC LIMIT ?""",
            (project_id, problem_family, float(min_confidence), int(limit)),
        ).fetchall()
        return [dict(r) for r in rows]

    def mark_reuse_result(self, lesson_id, success):
        if success:
            self.db.execute(
                "UPDATE lessons SET success_count=success_count+1,last_used_at=? WHERE lesson_id=?",
                (time.time(), lesson_id),
            )
        else:
            self.db.execute(
                "UPDATE lessons SET failure_count=failure_count+1,confidence=MAX(0.0,confidence-0.15),last_used_at=? WHERE lesson_id=?",
                (time.time(), lesson_id),
            )
        self.db.commit()

    def record_worker_result(self, project_id, worker_id, problem_family, success, cost_usd, latency_ms):
        self.db.execute(
            """INSERT INTO routing_stats(project_id,worker_id,problem_family,attempts,successes,total_cost,total_latency_ms)
          VALUES(?,?,?,?,?,?,?)
          ON CONFLICT(project_id,worker_id,problem_family) DO UPDATE SET
          attempts=attempts+1,successes=successes+excluded.successes,total_cost=total_cost+excluded.total_cost,
          total_latency_ms=total_latency_ms+excluded.total_latency_ms""",
            (project_id, worker_id, problem_family, 1, 1 if success else 0, float(cost_usd), float(latency_ms)),
        )
        self.db.commit()

    def best_workers(self, project_id, problem_family):
        rows = self.db.execute(
            """SELECT *,CASE WHEN attempts>0 THEN CAST(successes AS REAL)/attempts ELSE 0 END success_rate,
          CASE WHEN successes>0 THEN total_cost/successes ELSE 999999 END cost_per_success
          FROM routing_stats WHERE project_id=? AND problem_family=?
          ORDER BY success_rate DESC,cost_per_success ASC,total_latency_ms/MAX(attempts,1) ASC""",
            (project_id, problem_family),
        ).fetchall()
        return [dict(r) for r in rows]
