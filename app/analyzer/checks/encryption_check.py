"""FairPlay encryption state."""
from __future__ import annotations

from ..models import CATEGORY_BINARY, AnalysisContext, CheckResult, Finding, Severity, Status
from .base import Check


class EncryptionCheck(Check):
    id = "encryption"
    title = "App Store (FairPlay) Encryption"
    category = CATEGORY_BINARY
    weight = 0.6
    explanation = (
        "App Store binaries ship wrapped in FairPlay DRM (cryptid = 1). The "
        "operating system decrypts the executable in memory at launch. A binary "
        "whose cryptid is 0 is plaintext on disk — it can be disassembled, "
        "patched and re-signed, which is the very first step of almost every crack."
    )
    remediation = (
        "FairPlay cannot be relied on as a security control: any jailbroken "
        "device can dump the decrypted image. Treat the binary as readable by "
        "an attacker and lean on runtime integrity checks and server-side logic."
    )

    def run(self, ctx: AnalysisContext) -> CheckResult:
        m = ctx.macho
        if not m.parsed:
            return self.result(Status.ERROR, "Mach-O could not be parsed.", 0.5,
                               weight=0.3, error=m.error)
        if m.cryptid is None:
            return self.result(
                Status.INFO,
                "No LC_ENCRYPTION_INFO command present (already stripped, or a "
                "non-encrypted slice).",
                0.5, weight=0.3,
                findings=[Finding("LC_ENCRYPTION_INFO", "absent")],
            )
        if m.cryptid == 0:
            return self.result(
                Status.FAIL,
                "Binary is decrypted (cryptid = 0) and fully readable. Expected "
                "for an IPA dumped from a jailbroken device — but it means the "
                "code is wide open to static analysis and patching.",
                1.0, severity=Severity.HIGH,
                findings=[Finding("cryptid = 0", "FairPlay encryption stripped / not present")],
            )
        return self.result(
            Status.PASS,
            "Binary is FairPlay-encrypted (cryptid = 1) on disk.",
            0.0,
            findings=[Finding(f"cryptid = {m.cryptid}", "encryption intact")],
        )
