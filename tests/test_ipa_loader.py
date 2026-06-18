"""IPA loading error handling."""
from __future__ import annotations

import zipfile

import pytest

from app.analyzer.ipa_loader import IpaError, load_ipa


def test_missing_file(tmp_path):
    with pytest.raises(IpaError):
        load_ipa(str(tmp_path / "nope.ipa"), str(tmp_path / "out"))


def test_not_a_zip(tmp_path):
    bad = tmp_path / "bad.ipa"
    bad.write_bytes(b"this is not a zip archive")
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(IpaError):
        load_ipa(str(bad), str(out))


def test_zip_without_payload(tmp_path):
    z = tmp_path / "empty.ipa"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("README.txt", "no payload here")
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(IpaError):
        load_ipa(str(z), str(out))


def test_loads_synthetic_ipa(sample_ipa, tmp_path):
    bundle = load_ipa(sample_ipa, str(tmp_path / "out"))
    assert bundle.bundle_id == "com.example.demoapp"
    assert bundle.executable_name == "DemoApp"
    assert "Alamofire.framework" in bundle.frameworks
