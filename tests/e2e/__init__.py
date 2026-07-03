"""
E2E Test Configuration — Shared Constants
──────────────────────────────────────────
All test fixtures are in conftest.py (auto-loaded by pytest).
This module only defines constants and helper functions.

When running via Docker Compose test profile:
  TEST_BACKEND_URL=http://test-python-backend:8000

When running locally against a running backend:
  TEST_BACKEND_URL=http://localhost:18000
"""

import os
import logging

logger = logging.getLogger("e2e")

# ─── Configuration ──────────────────────────────────────────────

BACKEND_URL = os.environ.get("TEST_BACKEND_URL", "http://localhost:18000")
DEMO_MODE = os.environ.get("DEMO_MODE", "true").lower() in ("1", "true", "yes")

# Timeout for HTTP requests (seconds)
REQUEST_TIMEOUT = 30.0

# Maximum time to wait for backend readiness (seconds)
READINESS_TIMEOUT = 120.0


@pytest.fixture
def reference_data():
    """Reference dataset for drift monitoring."""
    return [
        {"feature_a": 1.0, "feature_b": 2.0, "feature_c": 3.0},
        {"feature_a": 1.1, "feature_b": 2.1, "feature_c": 3.1},
        {"feature_a": 0.9, "feature_b": 1.9, "feature_c": 2.9},
        {"feature_a": 1.2, "feature_b": 2.2, "feature_c": 3.2},
    ]


@pytest.fixture
def production_data():
    """Production dataset for drift monitoring."""
    return [
        {"feature_a": 1.0, "feature_b": 2.0, "feature_c": 3.0},
        {"feature_a": 1.1, "feature_b": 2.1, "feature_c": 3.1},
        {"feature_a": 0.9, "feature_b": 1.9, "feature_c": 2.9},
        {"feature_a": 1.2, "feature_b": 2.2, "feature_c": 3.2},
    ]
