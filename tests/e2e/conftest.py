"""
Pytest configuration for E2E pipeline integration tests.
─────────────────────────────────────────────────────────
Provides shared fixtures used across all test modules.
"""

import os
import time
import uuid
import logging

import httpx
import pytest

logger = logging.getLogger("e2e")

BACKEND_URL = os.getenv("TEST_BACKEND_URL", os.getenv("BACKEND_URL", "http://localhost:18000"))
MCP_URL = os.getenv("MCP_URL", "http://localhost:3002")
DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() in ("1", "true", "yes")

# Maximum time to wait for backend readiness (seconds)
READINESS_TIMEOUT = 120.0


# ═══════════════════════════════════════════════════════════════════
#  Backend URL
# ═══════════════════════════════════════════════════════════════════

@pytest.fixture(scope="session")
def backend_url() -> str:
    """Return the backend base URL."""
    return BACKEND_URL


# ═══════════════════════════════════════════════════════════════════
#  Auto-readiness probe — blocks until backend is healthy
# ═══════════════════════════════════════════════════════════════════

@pytest.fixture(scope="session", autouse=True)
def wait_for_backend(backend_url: str):
    """Poll /health until ready or timeout."""
    logger.info("Waiting for backend at %s ...", backend_url)
    start = time.time()
    attempt = 0
    while time.time() - start < READINESS_TIMEOUT:
        attempt += 1
        try:
            resp = httpx.get(f"{backend_url}/health", timeout=5.0)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") in ("ok", "degraded"):
                    logger.info("Backend ready (status=%s) after %.1fs", data["status"], time.time() - start)
                    return
        except (httpx.ConnectError, httpx.TimeoutException):
            pass
        wait = min(2 ** (attempt // 3), 10)
        logger.info("  Attempt %d: not ready, retrying in %ds...", attempt, wait)
        time.sleep(wait)

    pytest.fail(
        f"Backend at {BACKEND_URL} not ready after {READINESS_TIMEOUT}s. "
        f"Start it with: docker compose -f docker-compose.test.yml up -d --build"
    )


# ═══════════════════════════════════════════════════════════════════
#  HTTP Clients
# ═══════════════════════════════════════════════════════════════════

@pytest.fixture(scope="session")
def http_client() -> httpx.Client:
    """Shared HTTP client targeting the Python backend."""
    client = httpx.Client(
        base_url=BACKEND_URL,
        timeout=30.0,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    yield client
    client.close()


@pytest.fixture(scope="session")
def mcp_client() -> httpx.Client:
    """HTTP client targeting the MCP server."""
    client = httpx.Client(
        base_url=MCP_URL,
        timeout=30.0,
        headers={
            "Content-Type": "application/json",
            "X-MCP-User-Id": "test-user-e2e",
            "X-MCP-User-Role": "admin",
        },
    )
    yield client
    client.close()


# ═══════════════════════════════════════════════════════════════════
#  Test Data Fixtures
# ═══════════════════════════════════════════════════════════════════

@pytest.fixture(scope="session")
def model_id() -> str:
    """Unique model ID for the entire test session."""
    return f"e2e-test-model-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="session")
def sample_dataset() -> list[dict]:
    """Sample dataset for bias assessment."""
    return [
        {"gender": "male", "prediction": 1, "actual": 1},
        {"gender": "female", "prediction": 0, "actual": 1},
        {"gender": "male", "prediction": 1, "actual": 1},
        {"gender": "female", "prediction": 0, "actual": 0},
    ]


@pytest.fixture(scope="session")
def reference_data() -> list[dict]:
    """Reference data for drift monitoring."""
    return [
        {"feature_a": 1.0, "feature_b": 2.0, "feature_c": 3.0},
        {"feature_a": 1.5, "feature_b": 2.5, "feature_c": 3.5},
    ]


@pytest.fixture(scope="session")
def production_data() -> list[dict]:
    """Production data for drift monitoring."""
    return [
        {"feature_a": 1.1, "feature_b": 2.1, "feature_c": 3.1},
        {"feature_a": 1.6, "feature_b": 2.6, "feature_c": 3.6},
    ]
