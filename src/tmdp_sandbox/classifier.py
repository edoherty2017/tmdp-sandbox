"""Phase 2: scikit-learn classifier pipeline for security event classification.

Trains a calibrated classifier on labeled EventSpec data and produces
P(malicious) ∈ [0, 1] for each event. This probability is the p_catastrophic
input to the Phase 3 T-MDP decision layer.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .context_window import check_baseline_integrity, extract_context_features
from .event_spec import EventSpec, SecurityScenario
from .preprocessing import extract_features
from .risk import RiskAssessment


_NUMERIC_FEATURES = [
    "feat__in_baseline",
    "feat__is_suspicious_process",
    "feat__has_obfuscated_command",
    "feat__event_id",
    "feat__is_attack_eid",
    "feat__is_system_user",
    "feat__ctx_suspicious_proc_count",
    "feat__ctx_suspicious_eid_count",
    "feat__ctx_obfuscated_count",
    "feat__ctx_unique_processes",
    "feat__ctx_system_ratio",
    "feat__ctx_log_cleared",
    "feat__ctx_window_size",
]

_TEXT_FEATURES = [
    "text__command_line",
    "text__process_name",
    "text__parent_process",
]


def build_classifier_pipeline(*, model: str = "logistic") -> Pipeline:
    """Build an untrained scikit-learn pipeline.

    model: "logistic" (default, calibrated, fast) or "forest" (RandomForest).
    """
    text_transformers = [
        (f"tfidf_{col.replace('text__', '')}", TfidfVectorizer(max_features=500), col)
        for col in _TEXT_FEATURES
    ]
    numeric_transformer = ("numeric", StandardScaler(), _NUMERIC_FEATURES)

    preprocessor = ColumnTransformer(
        transformers=text_transformers + [numeric_transformer],
        remainder="drop",
    )

    if model == "logistic":
        base = LogisticRegression(
            class_weight="balanced",
            max_iter=1000,
            random_state=42,
        )
        estimator = CalibratedClassifierCV(base, cv=3, method="isotonic")
    elif model == "forest":
        base = RandomForestClassifier(
            n_estimators=100,
            class_weight="balanced",
            random_state=42,
        )
        estimator = CalibratedClassifierCV(base, cv=3, method="isotonic")
    else:
        raise ValueError(f"unknown model type: {model!r}; expected 'logistic' or 'forest'")

    return Pipeline([
        ("preprocessor", preprocessor),
        ("classifier", estimator),
    ])


def _to_dataframe(feature_dicts: list[dict[str, Any]]) -> "pd.DataFrame":
    """Convert list of feature dicts to a DataFrame with all expected columns."""
    df = pd.DataFrame(feature_dicts)
    for col in _TEXT_FEATURES + _NUMERIC_FEATURES:
        if col not in df.columns:
            df[col] = "" if col.startswith("text__") else 0.0
    # Ensure text columns are strings and numeric columns are float
    for col in _TEXT_FEATURES:
        df[col] = df[col].fillna("").astype(str)
    for col in _NUMERIC_FEATURES:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)
    return df


def train_classifier(
    feature_dicts: list[dict[str, Any]],
    labels: list[str],
    *,
    model: str = "logistic",
) -> Pipeline:
    """Train and return a fitted classifier pipeline.

    labels must be "benign" or "malicious". The pipeline outputs
    P(malicious) via predict_proba.
    """
    if len(feature_dicts) != len(labels):
        raise ValueError("feature_dicts and labels must have the same length")
    if not feature_dicts:
        raise ValueError("cannot train on empty dataset")

    pipeline = build_classifier_pipeline(model=model)
    binary_labels = [1 if lbl == "malicious" else 0 for lbl in labels]
    pipeline.fit(_to_dataframe(feature_dicts), binary_labels)
    return pipeline


def predict_proba_malicious(
    pipeline: Pipeline,
    feature_dicts: list[dict[str, Any]],
) -> list[float]:
    """Return P(malicious) for each feature dict."""
    if not feature_dicts:
        return []
    proba = pipeline.predict_proba(_to_dataframe(feature_dicts))
    classes = list(pipeline.classes_)
    malicious_col = classes.index(1) if 1 in classes else -1
    if malicious_col == -1:
        return [0.0] * len(feature_dicts)
    return [float(row[malicious_col]) for row in proba]


def save_classifier(pipeline: Pipeline, path: Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, path)


def load_classifier(path: Path) -> Pipeline:
    return joblib.load(path)


class MLCommandClassifier:
    """Wraps a trained scikit-learn pipeline as a risk assessor.

    Implements the same interface as ObservableFeatureRiskAssessor so it
    can be used as a drop-in replacement in the batch and policy layers.
    The score it returns is P(malicious) from the trained model.
    """

    assessor_id = "ml-command-classifier-v0"

    def __init__(
        self,
        pipeline: Pipeline,
        *,
        window_size: int = 10,
    ) -> None:
        self._pipeline = pipeline
        self._window_size = window_size

    @classmethod
    def from_file(cls, path: Path, **kwargs: Any) -> "MLCommandClassifier":
        return cls(load_classifier(path), **kwargs)

    def score_event(
        self,
        event: EventSpec,
        context_events: tuple[EventSpec, ...],
        decision_index: int,
    ) -> float:
        """Return P(malicious) ∈ [0, 1] for a single event.

        Deterministic override: event IDs in _ATTACK_EVENT_IDS (audit log cleared,
        scheduled task created/updated, service installed, account created, etc.) are
        definitively attack indicators regardless of which process fires them. The ML
        component handles all other events where process-level features are the signal.
        """
        from .preprocessing import _ATTACK_EVENT_IDS
        if event.event_id is not None and event.event_id in _ATTACK_EVENT_IDS:
            return 0.99

        context = extract_context_features(
            context_events, decision_index, window_size=self._window_size
        )
        integrity = check_baseline_integrity(event)
        features = extract_features(event, context, integrity)
        scores = predict_proba_malicious(self._pipeline, [features])
        return scores[0]

    def assess_event(
        self,
        event: EventSpec,
        context_events: tuple[EventSpec, ...],
        decision_index: int,
    ) -> RiskAssessment:
        """Return a full RiskAssessment for use in policy and batch layers."""
        score = self.score_event(event, context_events, decision_index)
        return RiskAssessment(
            assessor_id=self.assessor_id,
            action="EXECUTE",
            target_path=event.command_line[:120],
            score=score,
            rationale=f"ML classifier P(malicious)={score:.4f} for process={event.process_name!r}",
            raw_response=None,
            failure_mode=None,
        )
