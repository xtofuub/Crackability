"""Registry of all static checks, in display order."""
from __future__ import annotations

from .anti_debug_check import AntiDebugCheck
from .anti_tampering_check import AntiTamperCheck
from .binary_hardening_check import BinaryHardeningCheck
from .crypto_check import WeakCryptoCheck
from .debug_artifacts_check import DebugArtifactsCheck
from .encryption_check import EncryptionCheck
from .entitlement_storage_check import EntitlementStorageCheck
from .entitlements_check import EntitlementsCheck
from .frameworks_check import FrameworksCheck
from .jailbreak_check import JailbreakDetectionCheck
from .patchable_flags_check import PatchableFlagsCheck
from .protector_check import ProtectorCheck
from .receipt_check import ReceiptValidationCheck
from .secrets_check import SecretsCheck
from .ssl_pinning_check import SslPinningCheck
from .transport_security_check import TransportSecurityCheck


def all_checks() -> list:
    """Instantiate every check, in the order they should appear."""
    return [
        EncryptionCheck(),
        BinaryHardeningCheck(),
        JailbreakDetectionCheck(),
        AntiDebugCheck(),
        AntiTamperCheck(),
        ProtectorCheck(),
        ReceiptValidationCheck(),
        PatchableFlagsCheck(),
        EntitlementStorageCheck(),
        SecretsCheck(),
        WeakCryptoCheck(),
        FrameworksCheck(),
        TransportSecurityCheck(),
        SslPinningCheck(),
        EntitlementsCheck(),
        DebugArtifactsCheck(),
    ]
