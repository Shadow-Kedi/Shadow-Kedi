# pipeline/scorer.py
"""
A clean, minimal, REUSABLE interface to this project's trained detection
model -- decoupled from the file-based batch pipeline (risk_engine.py)
so another service (Backend's "anomaly-engine") can import and call it
directly on a per-user-day basis, without needing to run the whole
offline pipeline or understand its internals.

WHY THIS EXISTS (the real integration blocker, not a nice-to-have):
anomaly-engine's ingest schema (/v1/events -- 5 coarse event_type
buckets + a generic metadata dict, see wazuh_connector.py) is too
coarse for this project's feature engineering, which needs per-event
detail (destination_domain, bytes_sent, is_removable_media, etc.) to
compute the 18 day-level features this model was trained on. That
detail has to be extracted from the RAW Wazuh alert -- see
wazuh_loader.py, which already does this -- BEFORE anomaly-engine's own
coarsening step, not reconstructed after it. This module is the OTHER
half of that handoff: once rich per-event features exist and have been
aggregated to a user-day (via classifier_daily.py's build_daily_features,
the same aggregation this model was trained on), THIS is what turns
that into a risk score -- callable directly, no file I/O, no CLI.

Usage (from another service, e.g. anomaly-engine's own code):
    from pipeline.scorer import ShadowKediScorer

    scorer = ShadowKediScorer()  # loads the trained model once
    result = scorer.score_daily_features({
        "et_app_launch": 3, "et_login_event": 12, "has_file": 1,
        "weak_auth": 0, ...  # all 18 features the model expects --
                              # see scorer.feature_cols after construction
    })
    # -> {"risk_score": 0.9926, "risk_category": "Critical"}
"""

from pathlib import Path

import joblib

from pipeline.risk_categorization import categorize, classifier_boundaries


class ShadowKediScorer:
    def __init__(self, model_path: str = "data/models/ga_optimized_classifier.joblib",
                 classifier_low: float = 0.02, classifier_medium: float = 0.10,
                 classifier_high: float = 0.9926, classifier_critical: float = 0.9984):
        """
        Defaults for classifier_high/critical match this project's own
        real-data-validated, sweep-discovered thresholds (see
        risk_engine.py's print_classifier_threshold_sweep() history) --
        NOT the module's own generic defaults, which were tuned for a
        different (untuned) model. Override only if scoring with a
        different trained model than the one these defaults were found
        for.
        """
        model_path = Path(model_path)
        if not model_path.exists():
            raise FileNotFoundError(
                f"Trained model not found at {model_path}. Run "
                f"pipeline.genetic_optimizer first, or point model_path "
                f"at an existing bundle."
            )
        bundle = joblib.load(model_path)
        self.model = bundle["model"]
        self.feature_cols = bundle["feature_cols"]
        self.model_name = bundle.get("model_name", "unknown")
        self.boundaries = classifier_boundaries(
            classifier_low, classifier_medium, classifier_high, classifier_critical
        )

    def score_daily_features(self, daily_features: dict) -> dict:
        """
        daily_features: a dict keyed by this model's exact feature names
        (self.feature_cols after construction -- print it to see the
        full list; currently 18 day-level aggregated features, e.g.
        et_app_launch, has_file, weak_auth, bytes_sent_log, ...).
        These must be computed the SAME way classifier_daily.py's
        build_daily_features() computes them (event-type counts/shares,
        max/mean aggregates, etc.) -- a caller supplying differently-
        computed features will get a technically-valid but meaningless
        score, since the model was trained on this specific aggregation.

        Raises ValueError listing exactly which features are missing,
        rather than silently defaulting them to 0 -- a silent default
        would produce a confidently wrong score rather than a visible error.
        """
        missing = [f for f in self.feature_cols if f not in daily_features]
        if missing:
            raise ValueError(
                f"Missing required features: {missing}. "
                f"This model expects exactly: {self.feature_cols}"
            )
        x = [[daily_features[f] for f in self.feature_cols]]
        proba = float(self.model.predict_proba(x)[0][1])
        category = categorize(proba, self.boundaries)
        return {"risk_score": proba, "risk_category": category}

    def score_batch(self, rows: list) -> list:
        """rows: list of daily_features dicts, same shape as
        score_daily_features(). Returns one result dict per row, same
        order -- convenience wrapper, not a vectorized fast path (this
        model's day-level scale, ~300k rows/day at real project scale,
        doesn't need one; add batching here later if that changes)."""
        return [self.score_daily_features(row) for row in rows]


if __name__ == "__main__":
    # Quick manual smoke test / usage demo
    scorer = ShadowKediScorer()
    print(f"Loaded model: {scorer.model_name}")
    print(f"Required features ({len(scorer.feature_cols)}): {scorer.feature_cols}")
