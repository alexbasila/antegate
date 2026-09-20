# AnteGate v0.1.0 — release notes

Date: 21 September 2026. Status: research prototype. License: MIT.

## Most important sentence

> **The release demonstrates a control case in which a model whose deployment is
> already recorded in the Authority's history satisfies every ordinary admission
> evidence requirement yet remains ineligible, because the required
> pre-deployment condition did not exist before that deployment was recorded.**

## Contents

| File | Role |
| --- | --- |
| `antegate_v041.py` | Network trust domain: authority, trust service, two company gateways, signed revocation bundle, rollback protection, cache TTL, fail closed |
| `antegate_v05.py` | Adds the local police layer: ALLOW / INVESTIGATE / REVOKE_RECOMMENDED, never revoking by itself |
| `antegate_v06.py` | Evidence-based admission with source-attributed, cryptographically bound evidence |
| `antegate_v07.py` | Prospective admission: pre-deployment commitment and the LegacyAI control case |
| `antegate_release.py` | Runs every demo, both degraded-mode checks, writes the SHA-256 manifest and the freeze report |
| `README.md` | Question, core result, claim, architecture, run instructions, prior work |
| `SECURITY_LIMITATIONS.md` | Trust-model limits, stated rather than discovered |
| `ANTEGATE_RELEASE_v0.1.0_HASHES.txt` | SHA-256 of the released files, generated locally |

## Lineage

```text
004R1  network trust and rollback protection
005    assessment / sanction separation
006    evidence-based admission
007    prospective admission and non-retroactive eligibility
```

Each step was a separate commission with its own falsification list, and each run
regenerates a dated report.

## Fixed before first outreach

- The operator key named in a commitment must now equal the key in the identity
  evidence and the key that signed the deployment manifest. Previously only the
  operator name was compared, so a second holder with the same name and a
  different key could have built on another holder's commitment. New tampering
  test 8: `OPERATOR_KEY_BINDING_MISMATCH`.
- Claims narrowed to what is measured: the Authority's recorded deployment
  history rather than real-world deployment, and separate service gateways rather
  than independently operated organisations.
- Single-use is stated as holding for the demonstrated sequential execution.

## Notes

- Ed25519 is the only mode that starts by default. Without `cryptography` the
  program exits with code 2. The HMAC fallback runs only with `--allow-degraded`
  and is labelled `SECURITY_MODE = DEGRADED_HMAC_EXPLICITLY_ALLOWED`.
- Earlier internal prototypes used the working name SecureAI.
- No research feature was added after the final internal claim freeze.

## Known open work

Labelled violation set and calibration of the police thresholds; external
witnesses for the audit chains and for bootstrap monotonicity; authenticated
Authority control interface; key rotation; TLS; multi-authority governance; real
model agents inside the domain; binding to a real deployment artifact rather than
to a manifest.
