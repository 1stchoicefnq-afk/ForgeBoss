from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from typing import Any

SCHEMA_VERSION = 1

TEMPLATES: dict[str, dict[str, Any]] = {
    "web-saas": {
        "kind": "web_saas",
        "stack": {
            "frontend": "React + TypeScript + Vite",
            "styling": "Tailwind CSS",
            "backend": "Node.js API",
            "database": "PostgreSQL",
            "tests": ["Vitest", "Playwright"],
        },
        "preview": {"command": "npm run dev", "type": "web"},
    },
    "website": {
        "kind": "website",
        "stack": {
            "frontend": "React + TypeScript + Vite",
            "styling": "Tailwind CSS",
            "backend": "none unless required",
            "database": "none unless required",
            "tests": ["Vitest", "Playwright"],
        },
        "preview": {"command": "npm run dev", "type": "web"},
    },
    "expo-mobile": {
        "kind": "mobile_app",
        "stack": {
            "frontend": "Expo + React Native + TypeScript",
            "navigation": "Expo Router",
            "backend": "API selected during architecture",
            "database": "PostgreSQL when server data is required",
            "tests": ["Jest", "Expo/React Native checks"],
        },
        "preview": {"command": "npx expo start", "type": "mobile"},
    },
    "api-service": {
        "kind": "api_service",
        "stack": {
            "backend": "Python + FastAPI",
            "database": "PostgreSQL",
            "contract": "OpenAPI",
            "tests": ["pytest"],
        },
        "preview": {"command": "python -m uvicorn app.main:app", "type": "api"},
    },
    "desktop-app": {
        "kind": "desktop_app",
        "stack": {
            "frontend": "React + TypeScript",
            "desktop": "Electron",
            "backend": "Electron main process / local services",
            "database": "SQLite when persistence is required",
            "tests": ["Vitest", "Playwright"],
        },
        "preview": {"command": "npm run dev", "type": "desktop"},
    },
}

CAPABILITY_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("authentication", ("auth", "login", "sign in", "sign-up", "signup", "users")),
    ("payments", ("stripe", "payment", "billing", "subscription", "checkout")),
    ("database", ("database", "crm", "customers", "jobs", "records", "inventory")),
    ("scheduling", ("schedule", "scheduling", "calendar", "booking", "appointments")),
    ("files", ("upload", "attachments", "documents", "photos", "images")),
    ("realtime", ("realtime", "real-time", "chat", "live updates", "presence")),
    ("notifications", ("notification", "sms", "email alerts", "push notification")),
    ("maps", ("map", "maps", "gps", "location", "geolocation")),
    ("ai", (" ai ", "agent", "assistant", "receptionist", "llm", "openai", "anthropic")),
    ("admin", ("admin", "owner dashboard", "management dashboard", "dashboard")),
    ("multi_tenant", ("multi-tenant", "multitenant", "businesses", "organisations", "organizations")),
)

_TEMPLATE_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("expo-mobile", ("mobile app", "android", "iphone", "ios app", "react native", "expo")),
    ("desktop-app", ("desktop app", "electron", "windows app", "mac app")),
    ("website", ("landing page", "marketing site", "brochure site", "portfolio website", "static website")),
)


def _normalise_text(value: str) -> str:
    return " ".join(value.strip().split())


def _slugify(value: str) -> str:
    value = value.casefold()
    value = re.sub(r"[^a-z0-9]+", "-", value).strip("-")
    return value[:64] or "new-app"


def _extract_name(idea: str) -> str:
    patterns = (
        r"\bbuild\s+me\s+([A-Z][A-Za-z0-9_-]{1,40})\b",
        r"\bcalled\s+([A-Z][A-Za-z0-9_-]{1,40})\b",
        r"\bnamed\s+([A-Z][A-Za-z0-9_-]{1,40})\b",
    )
    for pattern in patterns:
        match = re.search(pattern, idea, flags=re.IGNORECASE)
        if match:
            return match.group(1)
    words = re.findall(r"[A-Za-z0-9]+", idea)
    return " ".join(words[:4]).title() if words else "New App"


def infer_template(idea: str) -> str:
    text = f" {_normalise_text(idea).casefold()} "
    for template_id, keywords in _TEMPLATE_KEYWORDS:
        if any(keyword in text for keyword in keywords):
            return template_id
    api_terms = (" api ", "rest api", "graphql api", "backend service", "microservice")
    ui_terms = (" dashboard", " page", " ui", " website", " app")
    if any(term in text for term in api_terms) and not any(term in text for term in ui_terms):
        return "api-service"
    return "web-saas"


def detect_capabilities(idea: str) -> list[str]:
    text = f" {_normalise_text(idea).casefold()} "
    found = [name for name, needles in CAPABILITY_RULES if any(needle in text for needle in needles)]
    if "database" not in found and any(x in found for x in ("authentication", "payments", "scheduling", "admin", "multi_tenant")):
        found.append("database")
    return sorted(set(found))


def _workstreams(template_id: str, capabilities: list[str]) -> list[dict[str, Any]]:
    streams: list[dict[str, Any]] = [
        {
            "id": "foundation",
            "role": "architect_builder",
            "objective": "Create the smallest runnable production-shaped skeleton and project conventions.",
            "scope": ["project configuration", "application shell", "shared types"],
            "depends_on": [],
        }
    ]
    if template_id not in ("website",):
        streams.append(
            {
                "id": "data-and-services",
                "role": "backend_builder",
                "objective": "Implement data contracts, persistence and service boundaries required by the blueprint.",
                "scope": ["server/data layer", "migrations", "API contracts"],
                "depends_on": ["foundation"],
            }
        )
    streams.append(
        {
            "id": "product-ui",
            "role": "frontend_builder",
            "objective": "Build complete user flows, responsive states and error/empty/loading behaviour.",
            "scope": ["routes/screens", "components", "client state"],
            "depends_on": ["foundation"],
        }
    )
    if capabilities:
        streams.append(
            {
                "id": "capabilities",
                "role": "feature_builder",
                "objective": "Implement requested product capabilities without widening beyond the blueprint.",
                "scope": capabilities,
                "depends_on": ["foundation"],
            }
        )
    streams.extend(
        [
            {
                "id": "quality",
                "role": "tester_reviewer",
                "objective": "Add focused unit/integration/e2e tests and adversarial regression coverage.",
                "scope": ["tests", "test fixtures", "quality evidence"],
                "depends_on": [s["id"] for s in streams],
            },
            {
                "id": "release-readiness",
                "role": "release_reviewer",
                "objective": "Verify build, security, configuration, accessibility and deployment readiness without deploying.",
                "scope": ["read-only release evidence", "release checklist"],
                "depends_on": ["quality"],
            },
        ]
    )
    return streams


def compile_blueprint(
    idea: str,
    *,
    name: str | None = None,
    template: str | None = None,
    capabilities: list[str] | None = None,
    constraints: list[str] | None = None,
    stack_overrides: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Compile a plain-language app idea into a deterministic ForgeBoss build blueprint.

    This function intentionally performs no model call. A model may improve or enrich the
    input before this stage, but the boundary handed to the controller is deterministic.
    """
    idea = _normalise_text(idea)
    if not idea:
        raise ValueError("idea must not be empty")
    template_id = template or infer_template(idea)
    if template_id not in TEMPLATES:
        raise ValueError(f"unknown template: {template_id}")

    detected = detect_capabilities(idea)
    merged_capabilities = sorted(set(detected + list(capabilities or [])))
    template_spec = deepcopy(TEMPLATES[template_id])
    if stack_overrides:
        for key, value in stack_overrides.items():
            if not isinstance(key, str) or not isinstance(value, str) or not value.strip():
                raise ValueError("stack_overrides must contain non-empty string values")
            template_spec["stack"][key] = value.strip()

    app_name = _normalise_text(name or _extract_name(idea))
    if not app_name:
        raise ValueError("name must not be empty")

    stable_input = {
        "idea": idea,
        "name": app_name,
        "template": template_id,
        "capabilities": merged_capabilities,
        "constraints": sorted(set(_normalise_text(x) for x in (constraints or []) if _normalise_text(x))),
        "stack": template_spec["stack"],
    }
    fingerprint = hashlib.sha256(
        json.dumps(stable_input, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    return {
        "schema": SCHEMA_VERSION,
        "kind": "forgeboss_app_blueprint",
        "blueprint_id": f"fbapp-{fingerprint[:16]}",
        "fingerprint_sha256": fingerprint,
        "app": {
            "name": app_name,
            "slug": _slugify(app_name),
            "idea": idea,
            "template": template_id,
            "kind": template_spec["kind"],
        },
        "stack": template_spec["stack"],
        "preview": template_spec["preview"],
        "capabilities": merged_capabilities,
        "constraints": stable_input["constraints"],
        "workstreams": _workstreams(template_id, merged_capabilities),
        "controller_contract": {
            "must_materialize_exact_file_scopes_before_execution": True,
            "must_use_isolated_workspace": True,
            "must_require_independent_review": True,
            "must_freeze_candidate_sha_before_review": True,
            "must_not_auto_deploy": True,
        },
        "provenance": {
            "compiler": "forgeboss.appbuilder.blueprint",
            "compiler_schema": SCHEMA_VERSION,
            "model_call_required": False,
        },
    }
