"""
Role-Based Access Control Middleware — MCP Tool Authorization
──────────────────────────────────────────────────────────────
Enforces granular tool-level permissions based on user roles.

Roles:
  - admin:   Full access to all MCP tools
  - auditor: Access to audit tools (not certificate generation)
  - viewer:  Read-only access to classification and scoring tools
  - api_key: Access scoped to the API key's declared permissions

NIST AI RMF GOVERN 1.2 — Tool access governance.
EU AI Act Art. 14 — Human oversight for tool access.
ISO/IEC 42001:2023 Clause 7.4.3 — Supply chain permission controls.
GDPR Art. 25 — Data protection by design (least privilege).
"""

from __future__ import annotations
import logging
import re
from typing import Any, Callable, Optional

from fastapi import HTTPException, Request, status
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger("rbac")

# ─── Roles ────────────────────────────────────────────────────────

ROLES = ("admin", "auditor", "viewer", "api_key")

# ─── Tool Permission Hierarchy ───────────────────────────────────
# Maps each role to the set of tools it may invoke.
# "api_key" is handled dynamically via the key's scope field.

ROLE_TOOLS: dict[str, set[str]] = {
    "admin": {
        "classify_ai_risk",
        "discover_supply_chain",
        "audit_supply_chain",
        "score_audit_weighted",
        "verify_human_oversight",
        "run_bias_assessment",
        "generate_dpia",
        "run_adversarial_tests",
        "generate_audit_certificate",
        "monitor_model_drift",
        "audit_session_memory",
        "audit_rag_quality",
        "audit_prompt_templates",
        "audit_agent_trust",
        "audit_tool_permissions",
        "classify_agent_autonomy",
        "assess_dpdp_compliance",
    },
    "auditor": {
        "classify_ai_risk",
        "discover_supply_chain",
        "audit_supply_chain",
        "score_audit_weighted",
        "verify_human_oversight",
        "run_bias_assessment",
        "generate_dpia",
        "run_adversarial_tests",
        "monitor_model_drift",
        "audit_session_memory",
        "audit_rag_quality",
        "audit_prompt_templates",
        "audit_agent_trust",
        "audit_tool_permissions",
        "classify_agent_autonomy",
        "assess_dpdp_compliance",
    },
    "viewer": {
        "classify_ai_risk",
        "audit_supply_chain",
        "score_audit_weighted",
    },
}

# ─── Minimum-Role Required Per Tool ──────────────────────────────
# A caller must hold at least this role to invoke the tool.

TOOL_PERMISSIONS: dict[str, str] = {
    "classify_ai_risk": "viewer",
    "discover_supply_chain": "auditor",
    "audit_supply_chain": "viewer",
    "score_audit_weighted": "viewer",
    "verify_human_oversight": "auditor",
    "run_bias_assessment": "auditor",
    "generate_dpia": "auditor",
    "run_adversarial_tests": "auditor",
    "generate_audit_certificate": "admin",
    "monitor_model_drift": "auditor",
    "audit_session_memory": "auditor",
    "audit_rag_quality": "auditor",
    "audit_prompt_templates": "auditor",
    "audit_agent_trust": "auditor",
    "audit_tool_permissions": "auditor",
    "classify_agent_autonomy": "auditor",
    "assess_dpdp_compliance": "auditor",
}

# ─── Expected Parameter Schemas Per Tool ──────────────────────────
# Used for input validation. Each key maps tool name → dict of
# parameter name → expected Python type(s).

TOOL_SCHEMAS: dict[str, dict[str, tuple[type, ...]]] = {
    "classify_ai_risk": {
        "modelId": (str,),
        "modelType": (str,),
        "sector": (str,),
        "usesProfiling": (bool,),
    },
    "audit_supply_chain": {
        "modelId": (str,),
        "deepScan": (bool,),
    },
    "score_audit_weighted": {
        "modelId": (str,),
        "riskTier": (dict, type(None)),
        "supplyChain": (dict, type(None)),
        "oversight": (dict, type(None)),
        "bias": (dict, type(None)),
        "dpia": (dict, type(None)),
        "adversarial": (dict, type(None)),
    },
    "verify_human_oversight": {
        "modelId": (str,),
        "hasHumanInTheLoop": (bool,),
        "hasKillSwitch": (bool,),
        "deploymentContext": (str,),
    },
    "run_bias_assessment": {
        "modelId": (str,),
        "datasetSample": (list,),
        "sensitiveFeatures": (list,),
        "fairnessThreshold": (int, float),
    },
    "generate_dpia": {
        "modelId": (str,),
        "dataController": (str,),
        "dpoName": (str,),
        "processingPurpose": (str,),
        "dataCategories": (list,),
    },
    "run_adversarial_tests": {
        "modelId": (str,),
        "testSuites": (list,),
    },
    "generate_audit_certificate": {
        "modelId": (str,),
        "weightedScore": (int, float),
        "tier": (str,),
        "compliant": (bool,),
        "issuerName": (str,),
    },
    "monitor_model_drift": {
        "modelId": (str,),
        "referenceData": (list,),
        "productionData": (list,),
        "features": (list,),
    },
    "audit_session_memory": {
        "modelId": (str,),
        "sessionId": (str,),
        "stmConfig": (dict,),
    },
    "audit_rag_quality": {
        "modelId": (str,),
        "vectorDbConfig": (dict,),
        "sampleQueries": (list,),
    },
    "audit_prompt_templates": {
        "modelId": (str,),
        "promptTemplates": (list,),
    },
    "audit_agent_trust": {
        "modelId": (str,),
        "agents": (list,),
    },
    "audit_tool_permissions": {
        "modelId": (str,),
        "toolRegistry": (list,),
        "accessLogs": (list,),
    },
    "classify_agent_autonomy": {
        "modelId": (str,),
        "agentType": (str,),
        "hasHumanOversight": (bool,),
        "canMakeDecisions": (bool,),
    },
    "discover_supply_chain": {
        "modelId": (str,),
    },
    "assess_dpdp_compliance": {
        "modelId": (str,),
        "dataFiduciary": (str,),
        "consentMechanism": (str,),
    },
}

# ─── Role Hierarchy (for min-role comparisons) ────────────────────

_ROLE_RANK: dict[str, int] = {
    "viewer": 0,
    "auditor": 1,
    "admin": 2,
    "api_key": -1,
}


def _role_rank(role: str) -> int:
    """Return numeric rank for a role; unknown roles rank below viewer."""
    return _ROLE_RANK.get(role, -1)


# ─── Permission Check Function ────────────────────────────────────


def check_tool_permission(role: str, tool_name: str) -> bool:
    """
    Return True if *role* is allowed to invoke *tool_name*.

    For the "api_key" role the check delegates to the caller,
    since API key scopes are resolved externally before this call.
    Callers should pre-resolve "api_key" to the effective role
    or use ``check_api_key_permission`` instead.
    """
    if tool_name not in TOOL_PERMISSIONS:
        return False

    if role == "api_key":
        return False

    required = TOOL_PERMISSIONS[tool_name]
    return _role_rank(role) >= _role_rank(required)


def check_api_key_permission(api_key_scopes: list[str], tool_name: str) -> bool:
    """
    Return True if an API key with the given *scopes* may invoke *tool_name*.

    API keys use explicit scope strings (tool names) rather than role
    inheritance. The tool must be listed in the key's scope array.
    """
    if not api_key_scopes:
        return False
    return tool_name in api_key_scopes


# ─── Input Validation Helpers ─────────────────────────────────────


def validate_tool_input(tool_name: str, params: dict[str, Any]) -> list[str]:
    """
    Validate that *params* match the expected schema for *tool_name*.

    Returns a list of validation error messages.  An empty list means
    the input is valid.
    """
    errors: list[str] = []
    schema = TOOL_SCHEMAS.get(tool_name)
    if schema is None:
        return errors

    for field, expected_types in schema.items():
        if field not in params:
            continue
        value = params[field]
        if value is not None and not isinstance(value, expected_types):
            type_names = " | ".join(t.__name__ for t in expected_types)
            errors.append(
                f"Parameter '{field}' for tool '{tool_name}' "
                f"expected {type_names}, got {type(value).__name__}"
            )

    return errors


def validate_required_fields(tool_name: str, params: dict[str, Any]) -> list[str]:
    """
    Return errors for missing required (non-Optional) fields.

    A field is considered required if it appears in TOOL_SCHEMAS and
    is not present in *params*.
    """
    errors: list[str] = []
    schema = TOOL_SCHEMAS.get(tool_name)
    if schema is None:
        return errors

    for field in schema:
        if field not in params:
            errors.append(
                f"Missing required parameter '{field}' for tool '{tool_name}'"
            )

    return errors


# ─── FastAPI Middleware ────────────────────────────────────────────
# This can be mounted via:
#   app.middleware("http")(rbac_middleware)
# or via the RBACMiddleware ASGI class below.

SKIP_PATHS = ("/health", "/api/auth/")


async def rbac_middleware(request: Request, call_next: Callable):
    """
    FastAPI middleware that enforces MCP tool-level RBAC.

    Extraction order for the user role:
      1. request.state.role  — set by auth_middleware upstream
      2. X-User-Role header  — direct override (testing / internal)
      3. JWT claims          — decoded by auth_middleware already

    API keys use X-API-Key header; their scopes are resolved from
    the ``request.state.scopes`` list set by upstream auth.
    """
    path = request.url.path
    method = request.method

    if any(path.startswith(p) for p in SKIP_PATHS):
        return await call_next(request)

    if not path.startswith("/api/"):
        return await call_next(request)

    # ── Resolve role ───────────────────────────────────────────
    role: str = getattr(request.state, "role", "")
    if not role:
        role = request.headers.get("X-User-Role", "")
    if not role:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "error": "missing_role",
                "detail": "No role found in token or X-User-Role header.",
            },
        )

    if role not in ROLES:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "error": "invalid_role",
                "detail": f"Unknown role '{role}'. Expected one of: {ROLES}",
            },
        )

    # ── Extract tool name from request body ────────────────────
    # Tool calls are POST requests with a JSON body containing a
    # "tool" or "toolName" field, or inferred from the endpoint path.
    tool_name = await _extract_tool_name(request)

    if tool_name is None:
        return await call_next(request)

    # ── Check permission ───────────────────────────────────────
    if role == "api_key":
        scopes: list[str] = getattr(request.state, "scopes", [])
        if not check_api_key_permission(scopes, tool_name):
            logger.warning(
                "RBAC denied api_key access to tool=%s scopes=%s",
                tool_name, scopes,
            )
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "error": "forbidden",
                    "detail": (
                        f"API key does not include scope for tool '{tool_name}'. "
                        f"Granted scopes: {scopes}"
                    ),
                },
            )
    else:
        if not check_tool_permission(role, tool_name):
            required = TOOL_PERMISSIONS.get(tool_name, "unknown")
            logger.warning(
                "RBAC denied role=%s access to tool=%s (requires %s)",
                role, tool_name, required,
            )
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "error": "forbidden",
                    "detail": (
                        f"Role '{role}' is not authorized to call tool '{tool_name}'. "
                        f"Required minimum role: '{required}'."
                    ),
                },
            )

    return await call_next(request)


async def _extract_tool_name(request: Request) -> Optional[str]:
    """
    Best-effort extraction of the MCP tool name from the request.

    Strategies (in order):
      1. JSON body field ``tool`` or ``toolName``
      2. Path segment after /api/ (e.g. /api/risk/classify → classify)
    """
    if request.method == "POST":
        try:
            body = await request.body()
            if body:
                import json
                data = json.loads(body)
                if isinstance(data, dict):
                    return data.get("tool") or data.get("toolName")
        except Exception:
            pass

    path = request.url.path
    segments = [s for s in path.strip("/").split("/") if s]
    if len(segments) >= 2:
        return segments[-1]

    return None


# ─── ASGI Middleware Class ────────────────────────────────────────


class RBACMiddleware:
    """
    ASGI middleware for MCP tool-level role-based access control.

    Mount after the auth middleware so that ``request.state.role``
    is already populated from the JWT.

    Usage::

        app.add_middleware(RBACMiddleware)
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if any(path.startswith(p) for p in SKIP_PATHS):
            await self.app(scope, receive, send)
            return

        if not path.startswith("/api/"):
            await self.app(scope, receive, send)
            return

        # Read headers from scope to determine role without consuming body
        headers = dict(scope.get("headers", []))
        role = _get_header_str(headers, b"x-user-role")
        # Also check auth state if available (set by upstream auth middleware)
        auth_state = scope.get("auth_state", {})
        if not role:
            role = auth_state.get("role", "")
        if not role:
            await self.app(scope, receive, send)
            return

        if role not in ROLES:
            resp = JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "error": "invalid_role",
                    "detail": f"Unknown role '{role}'. Expected one of: {ROLES}",
                },
            )
            await resp(scope, receive, send)
            return

        # Attempt to read tool name from scope query params or path
        tool_name = _tool_name_from_path(path)

        if tool_name and not check_tool_permission(role, tool_name):
            required = TOOL_PERMISSIONS.get(tool_name, "unknown")
            logger.warning(
                "RBAC denied role=%s access to tool=%s (requires %s)",
                role, tool_name, required,
            )
            resp = JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "error": "forbidden",
                    "detail": (
                        f"Role '{role}' is not authorized to call tool '{tool_name}'. "
                        f"Required minimum role: '{required}'."
                    ),
                },
            )
            await resp(scope, receive, send)
            return

        await self.app(scope, receive, send)


# ─── Internal Helpers ─────────────────────────────────────────────


def _get_header_str(headers: dict[bytes, bytes], key: bytes) -> str:
    """Extract a header value as a decoded string."""
    raw = headers.get(key)
    if raw is None:
        return ""
    return raw.decode("latin-1").strip()


def _tool_name_from_path(path: str) -> Optional[str]:
    """Infer tool name from the last meaningful path segment."""
    segments = [s for s in path.strip("/").split("/") if s]
    if len(segments) >= 3:
        candidate = segments[-1]
        if candidate in TOOL_PERMISSIONS:
            return candidate
    return None
