"""Signature / indicator database used by the static checks.

These are *static* indicators (strings, symbol names, Objective-C selectors,
framework names) that are observable in a decrypted Mach-O. They tell us what
protections an app ships with and what could make it easier to crack.
"""
from __future__ import annotations

# --------------------------------------------------------------------------- #
#  Jailbreak detection
# --------------------------------------------------------------------------- #
# Filesystem paths an app probes when checking for a jailbreak.
JAILBREAK_PATHS = [
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
    "/Applications/Installer.app",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/Library/MobileSubstrate/DynamicLibraries",
    "/usr/lib/libsubstrate.dylib",
    "/usr/lib/substrate",
    "/usr/lib/TweakInject",
    "/usr/sbin/sshd",
    "/usr/bin/ssh",
    "/bin/bash",
    "/bin/sh",
    "/etc/apt",
    "/private/var/lib/apt",
    "/private/var/lib/cydia",
    "/private/var/stash",
    "/private/var/tmp/cydia.log",
    "/usr/libexec/cydia",
    "/usr/libexec/sftp-server",
    "/var/jb",                    # rootless jailbreaks (Dopamine etc.)
    "/.installed_unc0ver",
    "/.bootstrapped_electra",
    "/jb/lzma",
    "/Applications/FlyJB.app",
    "/Applications/Snoop-it Config.app",
]

# URL schemes / tweak loaders probed by JB checks.
JAILBREAK_KEYWORDS = [
    "cydia://",
    "sileo://",
    "zbra://",
    "filza://",
    "undecimus://",
    "DYLD_INSERT_LIBRARIES",
    "MobileSubstrate",
    "SubstrateLoader",
    "TweakInject",
    "rootless",
]

# Names of jailbreak-detection libraries / classes / selectors.
JAILBREAK_SDKS = [
    "IOSSecuritySuite",
    "DTTJailbreakDetection",
    "JailbreakDetection",
    "JailMonkey",                 # React Native
    "flutter_jailbreak_detection",
    "RNJailMonkey",
    "isJailbroken",
    "amIJailbroken",
    "jailbreakTest",
    "isDeviceJailbroken",
    "checkForJailbreak",
    "JailbreakChecker",
    "FreeJailbreakDetection",
]

# --------------------------------------------------------------------------- #
#  Anti-debugging
# --------------------------------------------------------------------------- #
ANTIDEBUG_SYMBOLS = [
    "ptrace",
    "sysctl",
    "getppid",
    "csops",
    "task_get_exception_ports",
    "_ptrace",
    "syscall",
]
ANTIDEBUG_KEYWORDS = [
    "PT_DENY_ATTACH",
    "P_TRACED",
    "AmIBeingDebugged",
    "isDebuggerAttached",
    "antiDebug",
    "denyDebugger",
    "KERN_PROC",
    "CS_DEBUGGED",
]

# --------------------------------------------------------------------------- #
#  Anti-tampering / integrity / hook & injection detection
# --------------------------------------------------------------------------- #
ANTITAMPER_SYMBOLS = [
    "_dyld_image_count",
    "_dyld_get_image_name",
    "_dyld_get_image_header",
    "dladdr",
    "MGCopyAnswer",
]
ANTITAMPER_KEYWORDS = [
    "SignerIdentity",
    "embedded.mobileprovision",
    "CodeResources",
    "_CodeSignature",
    "integrityCheck",
    "checksumValidation",
    "tamperDetection",
    "verifyIntegrity",
    "FridaGadget",
    "frida-server",
    "frida",
    "libcycript",
    "cynject",
    "MSHookFunction",
    "MSHookMessageEx",
    "MSFindSymbol",
    "fishhook",
    "substrate",
    "_dyld_register_func_for_add_image",
]

# --------------------------------------------------------------------------- #
#  Monetization: StoreKit / receipts / subscription SDKs
# --------------------------------------------------------------------------- #
# Local (on-device) receipt handling — spoofable on a jailbroken device.
RECEIPT_LOCAL = [
    "appStoreReceiptURL",
    "transactionReceipt",
    "SKReceiptRefreshRequest",
    "verifyReceipt",
    "/verifyReceipt",
    "PKCS7_verify",
    "d2i_PKCS7",
    "PKCS7",
    "receipt.p7b",
]
# Classic StoreKit 1 usage.
STOREKIT1 = [
    "SKPaymentQueue",
    "SKPaymentTransaction",
    "SKProductsRequest",
    "SKMutablePayment",
    "paymentQueue:updatedTransactions",
]
# StoreKit 2 — cryptographically verified, server-checkable transactions.
STOREKIT2 = [
    "AppTransaction",
    "VerificationResult",
    "currentEntitlements",
    "Transaction.all",
    "StoreKit.Transaction",
    "jwsRepresentation",
]
# Apple validation endpoints (local validation that hits these is still weak).
APPLE_VERIFY_HOSTS = [
    "buy.itunes.apple.com",
    "sandbox.itunes.apple.com",
    "api.storekit.itunes.apple.com",
]
# Third-party subscription/IAP SDKs — these do server-side entitlement checks,
# which materially raises the difficulty of faking a subscription.
# name (searchable) -> human label
IAP_SDKS = {
    "RevenueCat": "RevenueCat",
    "RCPurchases": "RevenueCat",
    "api.revenuecat.com": "RevenueCat (API)",
    "Purchases.framework": "RevenueCat",
    "Adapty": "Adapty",
    "api.adapty.io": "Adapty (API)",
    "Qonversion": "Qonversion",
    "qonversion.io": "Qonversion (API)",
    "Superwall": "Superwall",
    "superwall.com": "Superwall (API)",
    "Glassfy": "Glassfy",
    "Purchasely": "Purchasely",
    "api.purchasely.com": "Purchasely (API)",
}

# Boolean "gate" methods — the #1 crack target. A jailbroken user patches the
# BOOL to always-true (or hooks it). Matched case-insensitively as substrings,
# so these are kept specific/compound to avoid false hits (e.g. no bare "isPro"
# which would match "isProcessing").
PREMIUM_FLAGS = [
    "isPremium", "isPremiumUser", "premiumUser", "userIsPremium", "premiumUnlocked",
    "isProUser", "isProVersion", "proVersion", "upgradeToPro",
    "isPaidUser", "isPaid", "isSubscribed", "isSubscriber",
    "hasActiveSubscription", "subscriptionActive", "activeSubscription",
    "isInSubscription", "inSubscription", "isSubscriptionActive", "subscriptionIsActive",
    "isActiveSubscriber", "hasSubscription",
    "isPurchased", "hasPurchased", "didPurchase",
    "isUnlocked", "unlockAll", "unlockPro", "unlockPremium", "unlockFull",
    "unlockFeature", "isFeatureUnlocked", "featureUnlocked",
    "removeAds", "isAdFree", "shouldShowAds",
    "isTrial", "trialExpired", "trialActive", "isExpired", "isFullVersion",
    "fullVersionUnlocked", "isVIP",
    "hasValidLicense", "isLicensed", "licenseValid", "isLicenseValid",
    "validateLicense", "verifyLicense", "checkLicense", "licenseCheck",
    "isActivated", "isRegistered", "isEntitled", "hasEntitlement",
    "checkEntitlement", "canAccessPremium",
]

# --------------------------------------------------------------------------- #
#  Weak cryptography & insecure APIs
# --------------------------------------------------------------------------- #
WEAK_CRYPTO = {
    "CC_MD5": "MD5 hashing (broken)",
    "CC_MD2": "MD2 hashing (broken)",
    "CC_MD4": "MD4 hashing (broken)",
    "CC_SHA1": "SHA-1 hashing (deprecated)",
    "kCCAlgorithmDES": "DES cipher (broken)",
    "kCCAlgorithm3DES": "3DES cipher (legacy)",
    "kCCAlgorithmRC4": "RC4 cipher (broken)",
    "kCCAlgorithmRC2": "RC2 cipher (legacy)",
    "kCCOptionECBMode": "ECB block mode (leaks structure)",
    "MD5_Init": "OpenSSL MD5 (broken)",
    "SHA1_Init": "OpenSSL SHA-1 (deprecated)",
    "DES_set_key": "OpenSSL DES (broken)",
    "RC4(": "RC4 cipher (broken)",
}
INSECURE_FUNCS = {
    "strcpy": "Unbounded string copy",
    "strcat": "Unbounded string concat",
    "sprintf": "Unbounded formatted write",
    "vsprintf": "Unbounded formatted write",
    "gets": "Unbounded console read",
    "system(": "Shell command execution",
    "popen": "Shell command execution",
    "srand": "Predictable PRNG seed",
}

# --------------------------------------------------------------------------- #
#  Hardcoded-secret patterns (high precision, single-literal matches)
# --------------------------------------------------------------------------- #
# (name, regex, severity)  severity: critical/high/medium
SECRET_PATTERNS = [
    ("AWS Access Key ID",     r"\bAKIA[0-9A-Z]{16}\b",                                   "critical"),
    ("AWS (ASIA) Key ID",     r"\bASIA[0-9A-Z]{16}\b",                                   "high"),
    ("Google API Key",        r"\bAIza[0-9A-Za-z\-_]{35}\b",                             "high"),
    ("Firebase Cloud Msg Key",r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b",            "high"),
    ("Stripe Live Secret",    r"\bsk_live_[0-9A-Za-z]{20,}\b",                           "critical"),
    ("Stripe Live Publishable",r"\bpk_live_[0-9A-Za-z]{20,}\b",                          "medium"),
    ("Stripe Restricted Key", r"\brk_live_[0-9A-Za-z]{20,}\b",                           "critical"),
    ("GitHub Token",          r"\bgh[pousr]_[0-9A-Za-z]{36,}\b",                         "critical"),
    ("Slack Token",           r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b",                       "high"),
    ("Twilio Account SID",    r"\bAC[0-9a-fA-F]{32}\b",                                  "high"),
    ("Twilio API Key",        r"\bSK[0-9a-fA-F]{32}\b",                                  "high"),
    ("SendGrid API Key",      r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",           "critical"),
    ("Mailgun Key",           r"\bkey-[0-9a-zA-Z]{32}\b",                                "high"),
    ("Square Access Token",   r"\bsq0atp-[0-9A-Za-z\-_]{22}\b",                          "high"),
    ("Private Key Block",     r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY", "critical"),
    ("JSON Web Token",        r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", "high"),
    ("Slack Webhook",         r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",       "medium"),
    ("Firebase DB URL",       r"https://[a-z0-9-]+\.firebaseio\.com",                    "low"),
]

# --------------------------------------------------------------------------- #
#  Third-party SDK fingerprints (framework names / install names / symbols)
# --------------------------------------------------------------------------- #
# token (searchable) -> (display name, category)
KNOWN_SDKS = {
    # Analytics / attribution
    "FirebaseAnalytics": ("Firebase Analytics", "Analytics"),
    "GoogleAnalytics": ("Google Analytics", "Analytics"),
    "Amplitude": ("Amplitude", "Analytics"),
    "Mixpanel": ("Mixpanel", "Analytics"),
    "Segment": ("Segment", "Analytics"),
    "Adjust": ("Adjust", "Attribution"),
    "AppsFlyer": ("AppsFlyer", "Attribution"),
    "Branch": ("Branch", "Attribution"),
    "Flurry": ("Flurry", "Analytics"),
    # Crash / monitoring
    "Crashlytics": ("Crashlytics", "Crash reporting"),
    "FirebaseCrashlytics": ("Firebase Crashlytics", "Crash reporting"),
    "Sentry": ("Sentry", "Crash reporting"),
    "Bugsnag": ("Bugsnag", "Crash reporting"),
    "Instabug": ("Instabug", "Crash reporting"),
    # Push / engagement
    "OneSignal": ("OneSignal", "Push / messaging"),
    "Braze": ("Braze", "Push / messaging"),
    "Appboy": ("Braze (Appboy)", "Push / messaging"),
    "Intercom": ("Intercom", "Support"),
    # Auth / social
    "FBSDKCoreKit": ("Facebook SDK", "Social login"),
    "GoogleSignIn": ("Google Sign-In", "Social login"),
    "GoogleMaps": ("Google Maps", "Maps"),
    # Networking / utilities
    "Alamofire": ("Alamofire", "Networking"),
    "AFNetworking": ("AFNetworking", "Networking"),
    "SDWebImage": ("SDWebImage", "Image loading"),
    "Kingfisher": ("Kingfisher", "Image loading"),
    "SnapKit": ("SnapKit", "Layout"),
    "RxSwift": ("RxSwift", "Reactive"),
    "Lottie": ("Lottie", "Animation"),
    "Realm": ("Realm", "Database"),
    "SQLCipher": ("SQLCipher", "Encrypted DB"),
    # Cross-platform runtimes
    "Flutter": ("Flutter", "Cross-platform runtime"),
    "hermes": ("React Native (Hermes)", "Cross-platform runtime"),
    "React": ("React Native", "Cross-platform runtime"),
    "UnityFramework": ("Unity", "Game engine"),
    "Cordova": ("Apache Cordova", "Hybrid runtime"),
    "Capacitor": ("Capacitor", "Hybrid runtime"),
    # Monetization (also surfaced by the receipt check)
    "RevenueCat": ("RevenueCat", "Monetization"),
    "Adapty": ("Adapty", "Monetization"),
    "Qonversion": ("Qonversion", "Monetization"),
    "Superwall": ("Superwall", "Monetization"),
    # Advertising / mediation networks
    "GADMobileAds": ("Google AdMob", "Advertising"),
    "GoogleMobileAds": ("Google AdMob", "Advertising"),
    "GADApplicationIdentifier": ("Google AdMob", "Advertising"),
    "GADBannerView": ("Google AdMob", "Advertising"),
    "AppLovin": ("AppLovin / MAX", "Advertising"),
    "ALSdk": ("AppLovin / MAX", "Advertising"),
    "applovin": ("AppLovin / MAX", "Advertising"),
    "UnityAds": ("Unity Ads", "Advertising"),
    "IronSource": ("ironSource", "Advertising"),
    "Vungle": ("Vungle (Liftoff)", "Advertising"),
    "AdColony": ("AdColony", "Advertising"),
    "Chartboost": ("Chartboost", "Advertising"),
    "InMobi": ("InMobi", "Advertising"),
    "FBAudienceNetwork": ("Meta Audience Network", "Advertising"),
    "Pangle": ("Pangle (TikTok)", "Advertising"),
    "BUAdSDK": ("Pangle (TikTok)", "Advertising"),
    # Commercial hardening / RASP (presence is a *good* sign)
    "GuardSquare": ("DexGuard / iXGuard (GuardSquare)", "App hardening"),
    "iXGuard": ("iXGuard (GuardSquare)", "App hardening"),
    "Appdome": ("Appdome", "App hardening"),
    "Promon": ("Promon SHIELD", "App hardening"),
    "Talsec": ("Talsec freeRASP", "App hardening"),
    "freeRASP": ("Talsec freeRASP", "App hardening"),
    "Verimatrix": ("Verimatrix", "App hardening"),
    "Arxan": ("Arxan / Digital.ai", "App hardening"),
    "Jscrambler": ("Jscrambler", "App hardening"),
}

# SDK names that indicate a commercial RASP / hardening product is present.
HARDENING_SDK_TOKENS = [
    "GuardSquare", "iXGuard", "Appdome", "Promon", "Talsec", "freeRASP",
    "Verimatrix", "Arxan", "Jscrambler",
]

# --------------------------------------------------------------------------- #
#  Commercial protectors / packers / obfuscators
# --------------------------------------------------------------------------- #
# Distinctive tokens (install names, runtime strings, vendor markers) keyed by
# product label. Presence is a strong defensive signal and names the product.
PROTECTORS = {
    "iXGuard / DexGuard (GuardSquare)": ["iXGuard", "DexGuard", "GuardSquare"],
    "Arxan / Digital.ai": ["Arxan", "EnsureIT", "GuardIT"],
    "Promon SHIELD": ["Promon", "no.promon", "PromonShield"],
    "Appdome": ["Appdome", "com.appdome"],
    "Talsec freeRASP": ["Talsec", "freeRASP", "TalsecRuntime"],
    "Verimatrix / whiteCryption": ["Verimatrix", "whiteCryption", "SmartProtection"],
    "DexProtector (Licel)": ["DexProtector"],
    "AppSealing": ["AppSealing", "AppSealingEngine"],
    "LIAPP": ["LIAPP"],
    "nProtect (INCA)": ["nProtect", "TachyonAppGuard"],
    "Jscrambler": ["Jscrambler"],
    "SwiftShield (obfuscation)": ["SwiftShield"],
    "Obfuscator-LLVM": ["obfuscator-llvm", "ollvm"],
}
# Mach-O section / segment name fragments some protectors add.
PROTECTOR_SECTIONS = [
    "__ixguard", "__arxan", "__promon", "__appdome", "__guardsq",
    "__llvm_obf", "__dexp", "__obfu",
]

# --------------------------------------------------------------------------- #
#  On-device entitlement storage (editable on a jailbroken device, no hook)
# --------------------------------------------------------------------------- #
# Keychain accessibility classes that leave an item readable whenever the device
# is unlocked (weaker than ...WhenUnlockedThisDeviceOnly + access control).
WEAK_KEYCHAIN_ACCESS = [
    "kSecAttrAccessibleAlways",
    "kSecAttrAccessibleAlwaysThisDeviceOnly",
    "AccessibleAlways",
]
# NSUserDefaults usage. Defaults are a plain plist a jailbroken user can edit.
USERDEFAULTS_TOKENS = [
    "NSUserDefaults", "standardUserDefaults", "setBool:forKey:",
]
# Known on-device caches of entitlement / customer-info state (UserDefaults,
# plist or keychain) that a cracker can edit directly to flip to premium.
ENTITLEMENT_CACHE_KEYS = [
    "RCBackup", "rc_purchaserInfo", "purchaserInfo",
    "AdaptyProfile", "adapty_profile",
    "qonversion_user", "entitlements.plist", "subscription_status.plist",
    "premium.plist", "license.plist",
]

# --------------------------------------------------------------------------- #
#  TLS certificate / public-key pinning
# --------------------------------------------------------------------------- #
# Strong, specific pinning indicators (generic SecTrustEvaluate is intentionally
# excluded; it appears in apps that do no pinning at all).
PINNING_TOKENS = [
    "TrustKit", "TSKPinningValidator", "TSKPublicKeyHashes", "kTSKPinnedDomains",
    "pinnedCertificates", "publicKeyHashes", "SSLPinningMode",
    "PinnedCertificatesTrustEvaluator", "PublicKeysTrustEvaluator",
    "ServerTrustManager", "certificatePinning", "evaluateForPinning",
    "AFSSLPinningModePublicKey", "AFSSLPinningModeCertificate",
]
# Indicators that the app makes network calls at all (so missing pinning matters).
NETWORK_SURFACE = [
    "https://", "http://", "NSURLSession", "URLSession", "CFNetwork",
    "Alamofire", "AFNetworking", "cronet",
]

# --------------------------------------------------------------------------- #
#  Debug / non-production artifacts
# --------------------------------------------------------------------------- #
DEBUG_ARTIFACTS = [
    "http://localhost",
    "https://localhost",
    "127.0.0.1",
    "10.0.2.2",
    ".ngrok.io",
    "staging.",
    "-staging",
    "dev-api.",
    "api-dev.",
    ".dev.",
    "test-api.",
    "TODO",
    "FIXME",
    "DEBUG_MODE",
    "NSLog",
    "DTXcode",
]
