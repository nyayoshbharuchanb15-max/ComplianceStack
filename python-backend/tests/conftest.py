# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Shared test fixtures for AI Governance backend tests.
"""

import pytest


@pytest.fixture
def sample_bias_dataset():
    """Standard bias test dataset with balanced protected attributes."""
    return [
        {"prediction": 1, "label": 1, "race": "A", "gender": "M", "age_group": "young"},
        {"prediction": 0, "label": 0, "race": "B", "gender": "F", "age_group": "old"},
        {"prediction": 1, "label": 1, "race": "A", "gender": "F", "age_group": "young"},
        {"prediction": 0, "label": 0, "race": "B", "gender": "M", "age_group": "old"},
        {"prediction": 1, "label": 1, "race": "A", "gender": "M", "age_group": "young"},
        {"prediction": 0, "label": 0, "race": "B", "gender": "F", "age_group": "old"},
    ]


@pytest.fixture
def sample_drift_reference():
    """Reference dataset for drift detection tests."""
    return [
        {"feature_a": 1.0, "feature_b": 2.0, "feature_c": 3.0},
        {"feature_a": 1.1, "feature_b": 2.1, "feature_c": 3.1},
        {"feature_a": 0.9, "feature_b": 1.9, "feature_c": 2.9},
        {"feature_a": 1.2, "feature_b": 2.2, "feature_c": 3.2},
    ]


@pytest.fixture
def sample_drift_production():
    """Production dataset for drift detection (slightly shifted)."""
    return [
        {"feature_a": 2.0, "feature_b": 3.0, "feature_c": 4.0},
        {"feature_a": 2.1, "feature_b": 3.1, "feature_c": 4.1},
        {"feature_a": 1.9, "feature_b": 2.9, "feature_c": 3.9},
        {"feature_a": 2.2, "feature_b": 3.2, "feature_c": 4.2},
    ]
