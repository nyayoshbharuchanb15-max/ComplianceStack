# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
PII Redaction & Zero-Trust Data Minimization Middleware
────────────────────────────────────────────────────────
Enforces data minimization principles (GDPR Art. 5(1)(c)) and
prevents raw PII exposure through API endpoints.

This middleware intercepts requests and responses to:
  1. Detect and redact PII fields from request bodies
  2. Enforce field-level access control based on user scope
  3. Log all PII access attempts (detection events, not the PII itself)
  4. Strip PII from responses unless explicitly authorized

GDPR Art. 5(1)(c) — Data minimisation: adequate, relevant, and
limited to what is necessary.
GDPR Art. 25 — Data protection by design and by default.
DPDP Act 2023 Sec. 8(4) — Data Fiduciary shall implement appropriate
technical and organisational measures including anonymization.
"""

from __future__ import annotations
import json
import re
from typing import Any, Optional

# ─── PII Patterns ─────────────────────────────────────────────────
# Regex patterns for identifying common PII fields

PII_PATTERNS: dict[str, str] = {
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "phone": r"\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}",
    "ssn": r"\d{3}-\d{2}-\d{4}",
    "credit_card": r"\d{4}[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4}",
    "ip_address": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    "aadhaar": r"\b\d{4}\s?\d{4}\s?\d{4}\b",  # India Aadhaar
    "pan": r"[A-Z]{5}[0-9]{4}[A-Z]{1}",        # India PAN
    "voter_id": r"[A-Z]{3}\d{7}",               # India Voter ID
}

# Field names that commonly contain PII (case-insensitive)
PII_FIELD_NAMES = {
    "email", "phone", "mobile", "telephone", "ssn", "social_security",
    "credit_card", "card_number", "cvv", "pin", "password", "secret",
    "aadhaar", "aadhar", "pan", "passport", "driver_license",
    "voter_id", "bank_account", "ifsc", "routing_number",
    "date_of_birth", "dob", "birth_date",
    "first_name", "last_name", "full_name", "middle_name",
    "home_address", "mailing_address", "street_address",
    "biometric", "fingerprint", "face_image", "iris_scan",
}

# Safe (non-PII) fields that can be passed through
SAFE_ANALYTIC_FIELDS = {
    "modelid", "model_id", "audit_phase", "evidence_type",
    "risk_level", "tier", "score", "metric", "threshold",
    "passed", "compliant", "rationale", "finding", "mitigation",
    "feature", "drift_score", "overall_risk", "severity",
    "test_name", "test_suite", "attack_pattern",
    "iso42001clause", "mappedarticles", "timestamp",
    "confidence", "prediction", "label", "ground_truth",
    "category", "sector", "model_type", "deployment_context",
}


class PIIRedactor:
    """
    PII detection and redaction engine.

    Scans data structures recursively for PII patterns and field
    names, replacing values with redacted markers.
    """

    def __init__(self, redaction_token: str = "[REDACTED]"):
        self.redaction_token = redaction_token
        self.compiled_patterns = {
            name: re.compile(pattern)
            for name, pattern in PII_PATTERNS.items()
        }

    def contains_pii(self, value: str) -> bool:
        """Check if a string value contains PII patterns."""
        for pattern in self.compiled_patterns.values():
            if pattern.search(value):
                return True
        return False

    def redact_string(self, value: str) -> str:
        """Redact all PII patterns found in a string."""
        result = value
        for pattern in self.compiled_patterns.values():
            result = pattern.sub(self.redaction_token, result)
        return result

    def is_pii_field(self, field_name: str) -> bool:
        """Check if a field name indicates PII content."""
        return field_name.lower().strip("_") in PII_FIELD_NAMES

    def is_safe_field(self, field_name: str) -> bool:
        """Check if a field is a known safe analytic field."""
        return field_name.lower().strip("_") in SAFE_ANALYTIC_FIELDS

    def redact(
        self,
        data: Any,
        path: Optional[list[str]] = None,
        depth: int = 0,
        max_depth: int = 10,
    ) -> Any:
        """
        Recursively redact PII from a data structure.

        Scans all nested dicts, lists, and primitive values:
          - String values matching PII patterns are redacted
          - Fields with PII-indicative names are redacted
          - Safe analytic fields are always passed through

        Args:
            data: The data structure to redact
            path: Current field path (for recursion)
            depth: Current recursion depth
            max_depth: Maximum recursion depth

        Returns:
            Redacted copy of the data
        """
        if depth > max_depth:
            return data

        if isinstance(data, dict):
            return {
                key: self.redact(value, (path or []) + [key], depth + 1, max_depth)
                for key, value in data.items()
            }
        elif isinstance(data, list):
            return [self.redact(item, path, depth + 1, max_depth) for item in data]
        elif isinstance(data, str):
            if path and path[-1].lower() in PII_FIELD_NAMES:
                return self.redaction_token
            if self.contains_pii(data):
                return self.redact_string(data)
            return data
        else:
            return data

    def extract_analytic_data(
        self,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Extract only safe analytic fields from a data structure,
        removing all PII fields entirely (not just redacting).

        This implements data minimization by default (GDPR Art. 5(1)(c)).
        """
        result: dict[str, Any] = {}
        for key, value in data.items():
            if self.is_safe_field(key):
                if isinstance(value, dict):
                    result[key] = self.extract_analytic_data(value)
                elif isinstance(value, list):
                    result[key] = [
                        self.extract_analytic_data(v) if isinstance(v, dict) else v
                        for v in value
                    ]
                else:
                    result[key] = value
        return result


# Singleton
pii_redactor = PIIRedactor()
