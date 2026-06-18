"""Unpack an .ipa, locate the Payload/*.app bundle and read its metadata."""
from __future__ import annotations

import os
import plistlib
import zipfile

from .models import AppBundle


class IpaError(Exception):
    pass


def _read_plist(path: str) -> dict:
    try:
        with open(path, "rb") as fh:
            return plistlib.load(fh) or {}
    except Exception:
        return {}


def _largest_icon(app_path: str, info: dict) -> bytes | None:
    """Return the bytes of the best app-icon PNG we can find in the bundle."""
    candidates: list[str] = []

    def collect(node):
        if isinstance(node, dict):
            files = node.get("CFBundleIconFiles") or node.get("CFBundleIconName")
            if isinstance(files, str):
                candidates.append(files)
            elif isinstance(files, list):
                candidates.extend([f for f in files if isinstance(f, str)])
            for v in node.values():
                collect(v)

    collect(info.get("CFBundleIcons"))
    collect(info.get("CFBundleIcons~ipad"))
    if "CFBundleIconFiles" in info:
        collect(info)

    # Resolve candidate base names against real files in the bundle root.
    try:
        root_files = os.listdir(app_path)
    except OSError:
        root_files = []

    matches: list[str] = []
    for base in candidates:
        for f in root_files:
            if f.lower().startswith(base.lower()) and f.lower().endswith(".png"):
                matches.append(os.path.join(app_path, f))
    # Fall back to anything that looks like an app icon.
    if not matches:
        for f in root_files:
            lf = f.lower()
            if lf.endswith(".png") and ("icon" in lf or lf.startswith("appicon")):
                matches.append(os.path.join(app_path, f))

    if not matches:
        return None
    best = max(matches, key=lambda p: os.path.getsize(p) if os.path.exists(p) else 0)
    try:
        with open(best, "rb") as fh:
            return fh.read()
    except OSError:
        return None


def load_ipa(ipa_path: str, dest_dir: str) -> AppBundle:
    """Extract *ipa_path* into *dest_dir* and return a populated AppBundle."""
    if not os.path.isfile(ipa_path):
        raise IpaError(f"File not found: {ipa_path}")

    try:
        with zipfile.ZipFile(ipa_path) as zf:
            # Guard against zip-slip.
            for member in zf.namelist():
                target = os.path.normpath(os.path.join(dest_dir, member))
                if not target.startswith(os.path.normpath(dest_dir)):
                    raise IpaError(f"Unsafe path in archive: {member}")
            zf.extractall(dest_dir)
    except zipfile.BadZipFile as exc:
        raise IpaError(f"Not a valid .ipa / zip archive: {exc}") from exc

    payload = os.path.join(dest_dir, "Payload")
    if not os.path.isdir(payload):
        raise IpaError("Archive has no Payload/ directory — not a valid .ipa")

    app_dirs = [d for d in os.listdir(payload) if d.endswith(".app")]
    if not app_dirs:
        raise IpaError("No .app bundle found inside Payload/")
    app_path = os.path.join(payload, app_dirs[0])

    info = _read_plist(os.path.join(app_path, "Info.plist"))
    exe_name = info.get("CFBundleExecutable", "")
    exe_path = os.path.join(app_path, exe_name) if exe_name else ""

    if not exe_path or not os.path.isfile(exe_path):
        # Best-effort: pick the largest non-resource file in the bundle root.
        root_files = [
            os.path.join(app_path, f)
            for f in os.listdir(app_path)
            if os.path.isfile(os.path.join(app_path, f)) and "." not in f
        ]
        if root_files:
            exe_path = max(root_files, key=os.path.getsize)
            exe_name = os.path.basename(exe_path)
        else:
            raise IpaError("Could not locate the main executable in the bundle")

    frameworks_dir = os.path.join(app_path, "Frameworks")
    frameworks = sorted(
        f for f in (os.listdir(frameworks_dir) if os.path.isdir(frameworks_dir) else [])
    )
    plugins_dir = os.path.join(app_path, "PlugIns")
    plugins = sorted(
        f for f in (os.listdir(plugins_dir) if os.path.isdir(plugins_dir) else [])
    )

    platforms = info.get("CFBundleSupportedPlatforms") or []
    bundle = AppBundle(
        ipa_path=ipa_path,
        app_path=app_path,
        executable_path=exe_path,
        executable_name=exe_name,
        bundle_id=info.get("CFBundleIdentifier", ""),
        display_name=info.get("CFBundleDisplayName") or info.get("CFBundleName") or exe_name,
        version=info.get("CFBundleShortVersionString", ""),
        build=str(info.get("CFBundleVersion", "")),
        min_os=str(info.get("MinimumOSVersion", "")),
        platforms=[str(p) for p in platforms] if isinstance(platforms, list) else [],
        sdk_name=str(info.get("DTSDKName", "")),
        info_plist=info,
        icon_data=_largest_icon(app_path, info),
        frameworks=frameworks,
        plugins=plugins,
        file_size=os.path.getsize(ipa_path),
    )
    return bundle
