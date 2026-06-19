"""Shared pytest fixtures. Tests are GUI-free (engine/report/models only), so
they run fast and headless."""
from __future__ import annotations

import pytest

from app.analyzer.engine import analyze
from tools.make_test_ipa import build_hardened_ipa, build_ipa


@pytest.fixture(scope="session")
def sample_ipa(tmp_path_factory) -> str:
    d = tmp_path_factory.mktemp("ipa")
    return build_ipa(str(d / "DemoApp.ipa"))


@pytest.fixture(scope="session")
def report(sample_ipa):
    return analyze(sample_ipa)


@pytest.fixture(scope="session")
def hardened_report(tmp_path_factory):
    d = tmp_path_factory.mktemp("hardened")
    return analyze(build_hardened_ipa(str(d / "Hardened.ipa")))


@pytest.fixture
def by_id(report):
    def _get(check_id: str):
        for r in report.results:
            if r.check_id == check_id:
                return r
        raise AssertionError(f"no check with id {check_id!r}")
    return _get
