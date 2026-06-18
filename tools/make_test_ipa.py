"""Generate a synthetic *decrypted* .ipa for end-to-end self-testing.

This crafts a minimal but valid arm64 Mach-O (with an LC_ENCRYPTION_INFO_64
load command whose cryptid is 0, and a __cstring section seeded with indicator
strings), a real PNG icon, an Info.plist and a couple of embedded frameworks —
then zips it as an .ipa. No real iOS app is needed to exercise the analyzer.
"""
from __future__ import annotations

import os
import plistlib
import struct
import sys
import zlib

# ---- Mach-O constants -------------------------------------------------- #
MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
MH_EXECUTE = 0x2
MH_FLAGS = 0x00200085  # NOUNDEFS | DYLDLINK | TWOLEVEL | PIE
LC_SEGMENT_64 = 0x19
LC_ENCRYPTION_INFO_64 = 0x2C
S_CSTRING_LITERALS = 0x2
VMBASE = 0x100000000

INDICATOR_STRINGS = [
    # jailbreak detection
    "/Applications/Cydia.app",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/bin/bash",
    "/usr/sbin/sshd",
    "cydia://package/com.example",
    # anti-debug
    "PT_DENY_ATTACH",
    "ptrace",
    "sysctl",
    "AmIBeingDebugged",
    # integrity / injection
    "_dyld_image_count",
    "frida",
    "MSHookFunction",
    # monetization (local receipt validation -> should FAIL)
    "appStoreReceiptURL",
    "SKPaymentQueue",
    "verifyReceipt",
    "https://buy.itunes.apple.com/verifyReceipt",
    # patchable premium / license boolean gates -> should WARN
    "isPremiumUnlocked",
    "hasValidLicense",
    "unlockAllFeatures",
    "removeAds",
    "isSubscribed",
    # weak crypto / unsafe
    "CC_MD5",
    "kCCOptionECBMode",
    "strcpy",
    # hardcoded secrets — split in source so the literal isn't a contiguous
    # secret (avoids scanners flagging the fixture); the generated IPA still
    # contains the full assembled values for the analyzer to detect.
    "AKIA" + "IOSFODNN7EXAMPLE",
    "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    + "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    # debug artefacts
    "http://localhost:8080/api",
    "staging.example.com",
    "Demo licence check OK",
]


def _seg_name(name: str) -> bytes:
    return name.encode().ljust(16, b"\x00")


def build_macho() -> bytes:
    blob = ("\x00".join(INDICATOR_STRINGS) + "\x00").encode("utf-8")

    header_size = 32
    seg_cmd_size = 72 + 80          # segment command + one section_64
    enc_cmd_size = 24
    headers_total = header_size + seg_cmd_size + enc_cmd_size
    file_size = headers_total + len(blob)
    vmsize = (file_size + 0x3FFF) & ~0x3FFF

    header = struct.pack(
        "<IiiIIIII",
        MH_MAGIC_64, CPU_TYPE_ARM64, 0x0, MH_EXECUTE,
        2, seg_cmd_size + enc_cmd_size, MH_FLAGS, 0,
    )

    segment = struct.pack(
        "<II16sQQQQiiII",
        LC_SEGMENT_64, seg_cmd_size, _seg_name("__TEXT"),
        VMBASE, vmsize, 0, file_size,
        7, 5, 1, 0,
    )
    section = struct.pack(
        "<16s16sQQIIIIIIII",
        _seg_name("__cstring"), _seg_name("__TEXT"),
        VMBASE + headers_total, len(blob), headers_total, 0,
        0, 0, S_CSTRING_LITERALS, 0, 0, 0,
    )
    encryption = struct.pack(
        "<IIIIII",
        LC_ENCRYPTION_INFO_64, enc_cmd_size,
        headers_total, len(blob), 0, 0,   # cryptid = 0  (decrypted)
    )

    return header + segment + section + encryption + blob


# ---- minimal PNG writer ------------------------------------------------ #
def _png_chunk(tag: bytes, data: bytes) -> bytes:
    return (struct.pack(">I", len(data)) + tag + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))


def make_png(size: int = 120, rgb=(76, 141, 255)) -> bytes:
    raw = bytearray()
    for y in range(size):
        raw.append(0)  # filter: none
        for x in range(size):
            # subtle gradient so it isn't a flat square
            r = min(255, rgb[0] + x // 4)
            g = min(255, rgb[1] - y // 6)
            b = rgb[2]
            raw += bytes((r, g, b))
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n"
            + _png_chunk(b"IHDR", ihdr)
            + _png_chunk(b"IDAT", zlib.compress(bytes(raw), 9))
            + _png_chunk(b"IEND", b""))


def make_info_plist() -> bytes:
    info = {
        "CFBundleExecutable": "DemoApp",
        "CFBundleIdentifier": "com.example.demoapp",
        "CFBundleDisplayName": "Demo App",
        "CFBundleName": "DemoApp",
        "CFBundleShortVersionString": "2.4.1",
        "CFBundleVersion": "2410",
        "MinimumOSVersion": "15.0",
        "CFBundleSupportedPlatforms": ["iPhoneOS"],
        "DTSDKName": "iphoneos17.4",
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
        "CFBundleIcons": {
            "CFBundlePrimaryIcon": {"CFBundleIconFiles": ["AppIcon60x60"]}
        },
    }
    return plistlib.dumps(info)


def build_ipa(out_path: str) -> str:
    import zipfile

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    app = "Payload/DemoApp.app/"
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(app + "Info.plist", make_info_plist())
        z.writestr(app + "DemoApp", build_macho())
        z.writestr(app + "AppIcon60x60@2x.png", make_png())
        # embedded frameworks (dir names drive SDK fingerprinting)
        for fw in ("Alamofire", "Lottie"):
            z.writestr(f"{app}Frameworks/{fw}.framework/{fw}", b"\x00stub\x00")
    return out_path


if __name__ == "__main__":
    dest = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(__file__), "sample", "DemoApp.ipa")
    path = build_ipa(dest)
    print("wrote", path, os.path.getsize(path), "bytes")
