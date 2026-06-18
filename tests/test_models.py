"""AnalysisContext search helpers."""
from __future__ import annotations

from app.analyzer.models import AnalysisContext, AppBundle, MachOInfo


def _ctx(strings=None, symbols=None, frameworks=None) -> AnalysisContext:
    bundle = AppBundle(ipa_path="x", app_path="x", executable_path="x")
    macho = MachOInfo(path="x")
    return AnalysisContext(
        bundle=bundle,
        macho=macho,
        strings=list(strings or []),
        symbols=set(symbols or []),
        framework_names=list(frameworks or []),
    )


def test_contains_case_insensitive_and_sensitive():
    c = _ctx(["/Applications/Cydia.app", "hello world"])
    assert c.contains("cydia")
    assert c.contains("Cydia", case_sensitive=True)
    assert not c.contains("cydia", case_sensitive=True)
    assert not c.contains("does-not-exist")


def test_contains_any():
    c = _ctx(["alpha", "beta"])
    assert c.contains_any(["zeta", "beta"])
    assert not c.contains_any(["zeta", "gamma"])


def test_find_returns_matching_strings():
    c = _ctx(["one cydia", "two cydia", "three"])
    hits = c.find("cydia", limit=5)
    assert len(hits) == 2


def test_regex_extracts_token():
    c = _ctx(["prefix AKIAIOSFODNN7EXAMPLE suffix"])
    hits = c.regex(r"AKIA[0-9A-Z]{16}")
    assert hits and hits[0][1] == "AKIAIOSFODNN7EXAMPLE"


def test_symbols_and_frameworks_searchable():
    c = _ctx([], symbols=["_ptrace", "_objc_release"], frameworks=["RevenueCat.framework"])
    assert c.has_symbol("_ptrace")
    assert c.find_symbols("objc")
    assert c.contains("revenuecat")
