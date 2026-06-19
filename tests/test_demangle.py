"""Swift identifier recovery used to de-blind the static checks on Swift apps."""
from __future__ import annotations

from app.analyzer import demangle


def test_swift_identifiers_recovers_words():
    s = "$s10RevenueCat15EntitlementInfoV8isActiveSbvg"
    ids = demangle.swift_identifiers(s)
    assert "RevenueCat" in ids
    assert "EntitlementInfo" in ids
    assert "isActive" in ids


def test_enrich_surfaces_gate_names():
    syms = ["$s5MyApp10SubManagerC16isInSubscriptionSbvg", "objc_msgSend"]
    extra = demangle.enrich(syms)
    assert "isInSubscription" in extra
    assert "SubManager" in extra


def test_non_mangled_symbols_yield_nothing():
    # ordinary C / ObjC symbols are not Swift-mangled, so nothing is recovered
    assert demangle.enrich(["objc_msgSend", "_objc_release", "ptrace"]) == set()
