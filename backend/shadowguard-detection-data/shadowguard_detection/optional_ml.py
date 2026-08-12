"""Optional, experimental tenant-local model. Never use it as a blocking decision."""


def isolation_forest_scores(features: list[list[float]]) -> list[float]:
    try:
        from sklearn.ensemble import IsolationForest
    except ImportError as exc:
        raise RuntimeError("Install the optional ML dependencies with: pip install -e '.[ml]'") from exc
    if len(features) < 10:
        raise ValueError("Need at least 10 aggregate tenant-local observations")
    model = IsolationForest(random_state=42, contamination="auto")
    return (-model.fit_predict(features)).astype(float).tolist()
