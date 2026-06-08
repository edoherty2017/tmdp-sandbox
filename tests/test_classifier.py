"""Tests for the Phase 2 ML classifier pipeline."""

import pytest

from tmdp_sandbox.classifier import (
    MLCommandClassifier,
    build_classifier_pipeline,
    predict_proba_malicious,
    train_classifier,
)
from tmdp_sandbox.event_spec import EventSpec
from tmdp_sandbox.preprocessing import extract_features_for_sequence


def _benign_events(n: int = 20) -> list[EventSpec]:
    return [
        EventSpec(
            process_name="svchost.exe",
            command_line=f"C:\\Windows\\system32\\svchost.exe -k netsvcs {i}",
            user_name="SYSTEM",
            parent_process="services.exe",
            event_id=4688,
            label="benign",
        )
        for i in range(n)
    ]


def _malicious_events(n: int = 20) -> list[EventSpec]:
    return [
        EventSpec(
            process_name="powershell.exe",
            command_line=f"powershell.exe -noprofile -executionpolicy bypass -enc aQBlAHgA{i:04d}",
            user_name="user",
            parent_process="cmd.exe",
            event_id=4688,
            label="malicious",
        )
        for i in range(n)
    ]


def test_build_classifier_pipeline_logistic():
    pipeline = build_classifier_pipeline(model="logistic")
    assert pipeline is not None


def test_build_classifier_pipeline_forest():
    pipeline = build_classifier_pipeline(model="forest")
    assert pipeline is not None


def test_build_classifier_pipeline_rejects_unknown_model():
    with pytest.raises(ValueError, match="unknown model type"):
        build_classifier_pipeline(model="xgboost")


def test_train_classifier_produces_fitted_pipeline():
    events = _benign_events(15) + _malicious_events(15)
    feature_dicts, labels = extract_features_for_sequence(events)
    pipeline = train_classifier(feature_dicts, labels)
    scores = predict_proba_malicious(pipeline, feature_dicts)
    assert len(scores) == len(events)
    assert all(0.0 <= s <= 1.0 for s in scores)


def test_train_classifier_rejects_empty_data():
    with pytest.raises(ValueError, match="empty dataset"):
        train_classifier([], [])


def test_trained_classifier_separates_obvious_cases():
    """With clearly distinct training and test data the classifier should score
    obvious malicious events higher than obvious benign events on average."""
    train_events = _benign_events(30) + _malicious_events(30)
    feature_dicts, labels = extract_features_for_sequence(train_events)
    pipeline = train_classifier(feature_dicts, labels)

    test_benign = _benign_events(5)
    test_malicious = _malicious_events(5)
    test_events = test_benign + test_malicious
    test_features, _ = extract_features_for_sequence(test_events)
    scores = predict_proba_malicious(pipeline, test_features)

    avg_benign = sum(scores[:5]) / 5
    avg_malicious = sum(scores[5:]) / 5
    assert avg_malicious > avg_benign, (
        f"expected malicious avg ({avg_malicious:.3f}) > benign avg ({avg_benign:.3f})"
    )


def test_ml_command_classifier_score_is_in_unit_interval():
    train_events = _benign_events(20) + _malicious_events(20)
    feature_dicts, labels = extract_features_for_sequence(train_events)
    pipeline = train_classifier(feature_dicts, labels)
    clf = MLCommandClassifier(pipeline)

    test_event = _malicious_events(1)[0]
    all_events = tuple(train_events + [test_event])
    score = clf.score_event(test_event, all_events, decision_index=len(all_events) - 1)
    assert 0.0 <= score <= 1.0


def test_ml_command_classifier_assess_event_returns_risk_assessment():
    train_events = _benign_events(20) + _malicious_events(20)
    feature_dicts, labels = extract_features_for_sequence(train_events)
    pipeline = train_classifier(feature_dicts, labels)
    clf = MLCommandClassifier(pipeline)

    test_event = _benign_events(1)[0]
    all_events = tuple(train_events + [test_event])
    assessment = clf.assess_event(test_event, all_events, decision_index=len(all_events) - 1)
    assert assessment.assessor_id == "ml-command-classifier-v0"
    assert 0.0 <= assessment.score <= 1.0
    assert assessment.failure_mode is None
