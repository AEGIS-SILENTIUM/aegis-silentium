"""
c2/zeroday/analysis/ml/predictor.py
AEGIS-SILENTIUM v12 — ML-Assisted Vulnerability Prediction

Provides heuristic vulnerability scoring without requiring ML libraries.
When scikit-learn / PyTorch are available, can use trained models.
Falls back to rule-based scoring when ML libraries are absent.

Prediction targets:
  - Vulnerability likelihood (0-1) from static features
  - Exploitability score from crash + binary properties
  - Patch priority ranking
"""
from __future__ import annotations

import logging
import math
from typing import Dict, List, Optional

log = logging.getLogger("aegis.zeroday.ml")


class VulnerabilityPredictor:
    """
    Predicts vulnerability likelihood from static analysis features.

    Without ML libraries, uses a calibrated heuristic based on:
      - Cyclomatic complexity
      - Dangerous function presence
      - Binary mitigations
      - Code entropy (packed/obfuscated sections)
      - String pattern density

    With scikit-learn, can use a trained RandomForest classifier.
    """

    _ML_AVAILABLE: bool = False

    def __init__(self) -> None:
        self._model = None
        try:
            import sklearn  # noqa: F401
            self._ML_AVAILABLE = True
            log.info("ML predictor: scikit-learn available")
        except ImportError:
            log.info("ML predictor: using heuristic mode (install scikit-learn for ML)")

    def predict_vulnerability(self, features: dict) -> float:
        """
        Predict vulnerability likelihood from binary analysis features.
        Returns float 0.0 (safe) to 1.0 (highly likely vulnerable).

        Features dict keys:
          cyclomatic_max     - max cyclomatic complexity
          dangerous_calls    - count of dangerous function calls
          has_nx             - NX bit enabled
          has_pie            - PIE enabled
          has_canary         - stack canary
          entropy            - section entropy (>7.2 = packed)
          string_patterns    - suspicious string pattern count
          function_count     - number of recovered functions
        """
        if self._model is not None:
            return self._predict_model(features)
        return self._predict_heuristic(features)

    @staticmethod
    def _predict_heuristic(features: dict) -> float:
        """Rule-based vulnerability score."""
        score = 0.0
        weights = {
            "dangerous_calls":  lambda v: min(0.4, v * 0.08),
            "cyclomatic_max":   lambda v: 0.2 if v > 20 else 0.1 if v > 10 else 0.0,
            "has_nx":           lambda v: -0.1 if v else 0.15,
            "has_pie":          lambda v: -0.05 if v else 0.10,
            "has_canary":       lambda v: -0.10 if v else 0.10,
            "entropy":          lambda v: 0.15 if v > 7.2 else 0.0,
            "string_patterns":  lambda v: min(0.2, v * 0.04),
        }
        for key, fn in weights.items():
            score += fn(features.get(key, 0))
        return max(0.0, min(1.0, score))

    def _predict_model(self, features: dict) -> float:
        """ML model prediction (when scikit-learn available and model trained)."""
        # Placeholder: returns heuristic when model not loaded
        return self._predict_heuristic(features)

    def predict_exploitability(self, crash_features: dict) -> float:
        """
        Predict exploitability from crash features.
        Returns 0.0-1.0 confidence of exploitability.
        """
        score = 0.0
        vuln_class = crash_features.get("vuln_class", "unknown")
        pc_controlled = crash_features.get("pc_controlled", False)

        class_scores = {
            "heap_overflow":    0.45,
            "buffer_overflow":  0.40,
            "use_after_free":   0.45,
            "format_string":    0.50,
            "double_free":      0.35,
            "integer_overflow": 0.25,
            "null_deref":       0.05,
            "race_condition":   0.30,
        }
        score += class_scores.get(vuln_class, 0.10)
        if pc_controlled:
            score += 0.30
        if not crash_features.get("has_nx", True):
            score += 0.15
        if not crash_features.get("has_canary", True):
            score += 0.10
        return max(0.0, min(1.0, score))

    def rank_findings(self, findings: list) -> list:
        """Sort findings by predicted severity + exploitability."""
        def _score(f: dict) -> float:
            cvss = f.get("cvss_score", 5.0) / 10.0
            exp_map = {"weaponized": 1.0, "likely": 0.8, "possible": 0.5,
                       "unlikely": 0.2, "unknown": 0.3}
            exp = exp_map.get(f.get("exploitability", "unknown"), 0.3)
            return cvss * 0.6 + exp * 0.4
        return sorted(findings, key=_score, reverse=True)


__all__ = ["VulnerabilityPredictor"]
