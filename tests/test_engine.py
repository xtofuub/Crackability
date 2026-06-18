"""End-to-end engine behaviour against the synthetic decrypted IPA."""
from __future__ import annotations

from app.analyzer.models import Severity, Status


def test_report_shape(report):
    assert 0 <= report.score <= 100
    assert report.verdict in {"Low", "Moderate", "High", "Very High"}
    assert len(report.results) == 13
    assert sum(report.counts.values()) == 13


def test_macho_parsed(report):
    m = report.macho
    assert m.parsed is True
    assert m.arch == "ARM64"
    assert m.is_pie is True
    assert m.cryptid == 0


def test_encryption_decrypted(by_id):
    r = by_id("encryption")
    assert r.status is Status.FAIL
    assert r.risk == 1.0


def test_hardcoded_secrets(by_id):
    r = by_id("hardcoded_secrets")
    assert r.status is Status.FAIL
    assert r.severity is Severity.CRITICAL
    types = {f.detail for f in r.findings}
    assert {"AWS Access Key ID", "Stripe Live Secret", "JSON Web Token"} <= types
    # the actual matched key is surfaced (not redacted)
    assert "AKIAIOSFODNN7EXAMPLE" in {f.label for f in r.findings}


def test_receipt_local_validation_fails(by_id):
    r = by_id("receipt_validation")
    assert r.status is Status.FAIL
    assert r.weight > 0


def test_patchable_flags_detected(by_id):
    r = by_id("patchable_flags")
    assert r.status is Status.WARN
    assert r.weight > 0
    labels = {f.label for f in r.findings}
    # seeded gates: isPremiumUnlocked → isPremium, hasValidLicense, unlockAll, removeAds
    assert {"hasValidLicense", "removeAds"} <= labels


def test_jailbreak_detected(by_id):
    r = by_id("jailbreak_detection")
    assert r.status is Status.PASS
    assert len(r.findings) >= 3


def test_anti_debug_detected(by_id):
    r = by_id("anti_debug")
    assert r.status is Status.PASS


def test_weak_crypto(by_id):
    r = by_id("weak_crypto")
    assert r.status is Status.WARN
    labels = {f.label for f in r.findings}
    assert "CC_MD5" in labels


def test_frameworks_informational(by_id):
    r = by_id("frameworks")
    assert r.status is Status.INFO
    assert r.weight == 0.0


def test_ats_disabled(by_id):
    r = by_id("transport_security")
    assert r.status is Status.WARN


def test_every_result_has_metadata(report):
    for r in report.results:
        assert r.title and r.category
        assert 0.0 <= r.risk <= 1.0
        assert r.explanation or r.status is Status.ERROR
