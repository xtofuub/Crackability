# Skill: Conduct an iOS Crackability Assessment

A step-by-step guide (for a human or an AI agent driving the MCP server) on how to
**search a decrypted `.ipa` for crackability weaknesses and report them**. This is
an *assessment* workflow — it measures how resistant an app is to piracy / patching
/ subscription bypass and produces findings a developer can use to harden the app.
It does **not** unlock, flip, forge, or modify anything.

> **Authorized use only.** Run against apps you own, apps you are contracted to
> test, or your own device for research. Use the output to *harden* apps and to
> document weaknesses — not to bypass paid functionality.

---

## 1. Inputs

- A **decrypted** `.ipa` (FairPlay-stripped). Either:
  - dumped from a jailbroken device you control (the desktop app's Device panel), or
  - supplied by the app owner.
- Encrypted App Store `.ipa`s will read `cryptid != 0` and most string-based checks
  will see nothing useful — decrypt first.

## 2. Run a search

**Via the MCP server** (for agents/tools):
1. Start it: `python mcp_server.py` (stdio).
2. Call `list_checks` to see what will run.
3. Call `analyze_ipa(ipa_path="/abs/path/App.ipa")` → returns `{ ok, report }`.
4. Call `scoring_guide` to interpret the band.

**Via the CLI** (equivalent, for humans):
```
python main.py --cli /abs/path/App.ipa --json report.json --html report.html
```

**Via the desktop app:** Open `.ipa` (or Device → dump) → read the Results screen.

## 3. What the search looks at

| Category | What it means for crackability |
|---|---|
| **Encryption (FairPlay)** | `cryptid == 0` → binary is decrypted and fully readable/patchable. |
| **Binary hardening** | Missing PIE / stack canary / ARC / PAC = easier to analyze and patch. |
| **Jailbreak / anti-debug / anti-tamper** | Present = harder dynamic analysis; absent = runs unmodified on a JB device. |
| **Receipt / subscription validation** | *Local-only* validation is forgeable; *server-validated* is robust. |
| **Patchable premium / license flags** | Boolean gates (`isPremium`, `isSubscribed`, …) found in the binary — candidates a cracker would flip. **Detected and reported**, so the dev can move the decision server-side. |
| **Hardcoded secrets** | API keys/tokens embedded in the binary (shown in full so the owner can rotate them). |
| **Weak crypto** | MD5/SHA1/DES/ECB and similar. |
| **ATS / entitlements / debug artifacts** | Misconfig and leftover debug surface. |

## 4. Interpret the result

- **Score 0-100** with a verdict band (`low` → `critical`); see `scoring_guide`.
- Read each finding's `summary`, `findings` (evidence), and `remediation`.
- The strongest signal: a money-critical decision (premium/subscription) made
  **client-side** (a local boolean, or a locally-validated receipt) → flag as a
  high-risk weakness and recommend **server-side validation + signed/remote
  entitlements**.

## 5. Optional on-device assessment (your own device)

The desktop Device panel can, against a device you control, **observe** runtime
behaviour (does jailbreak detection fire? is the receipt validated against a
server? what purchase SDK is in use?) to confirm whether a statically-suspected
weakness is real. Treat this as evidence-gathering for the report.

## 6. Report

For each weakness: **what** (the finding), **evidence** (class/selector/string),
**why it matters** (crackability impact), and **the fix** (server-side validation,
keychain access control, obfuscated/remote entitlements, receipt signing). That
hardening guidance is the deliverable.
