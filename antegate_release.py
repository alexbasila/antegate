#!/usr/bin/env python3
# =============================================================================
# ANTEGATE v0.1.0  -  antegate_release.py
# -----------------------------------------------------------------------------
# Artifact provenance:
#   Script    : antegate_release.py
#   Purpose   : run every falsification demo, the two degraded-mode checks,
#               write the SHA-256 manifest and the final freeze report.
#   Parents   : antegate_v041.py, antegate_v05.py, antegate_v06.py,
#               antegate_v07.py
#   Created   : 2026-09-21
#   Run       : python antegate_release.py
#   Writes    : ANTEGATE_RELEASE_v0.1.0_HASHES.txt
#               antegate/ANTEGATE_FINAL_FREEZE_<UTC>.md
#   Exit code : 0 when every check passes, 1 otherwise. Do not release on 1.
#
# Public release lineage:
# AnteGate v0.1.0 derives from the internal SecureAI prototype series
# SECUREAI_004R1 -> 005 -> 006 -> 007. No research feature was added after the
# final internal claim freeze.
# =============================================================================

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

RELEASE = "AnteGate v0.1.0"
DEMOS = [
    ("antegate_v041.py", "ANTEGATE_004R1_REPORT_*.md", "network trust + rollback (004R1)"),
    ("antegate_v05.py", "ANTEGATE_005_REPORT_*.md", "assessment / sanction split (005)"),
    ("antegate_v06.py", "ANTEGATE_006_REPORT_*.md", "evidence-based admission (006)"),
    ("antegate_v07.py", "ANTEGATE_007_REPORT_*.md", "prospective admission (007)"),
]
FILES = ["antegate_v041.py", "antegate_v05.py", "antegate_v06.py", "antegate_v07.py",
         "antegate_release.py", "README.md", "RELEASE_NOTES_v0.1.0.md",
         "SECURITY_LIMITATIONS.md", "LICENSE"]
HASH_FILE = Path("ANTEGATE_RELEASE_v0.1.0_HASHES.txt")
REPORT_DIR = Path("antegate")


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def run(args, env_extra=None, timeout=900):
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    p = subprocess.run([sys.executable] + args, capture_output=True, text=True,
                       env=env, timeout=timeout)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def newest(pattern: str):
    hits = sorted(REPORT_DIR.glob(pattern), key=lambda p: p.stat().st_mtime)
    return hits[-1] if hits else None


def main() -> None:
    missing = [f for f in FILES if not Path(f).exists()]
    if missing:
        print(f"ABORT: missing release files: {missing}")
        sys.exit(2)

    rows, all_ok = [], True
    legacy_control = "NOT FOUND"

    for script, pattern, label in DEMOS:
        code, _ = run([script, "--demo"])
        report = newest(pattern)
        text = report.read_text(encoding="utf-8") if report else ""
        verdict = "PASS" if ("test: PASS" in text and "test: FAIL" not in text) else "FAIL"
        mode = (re.search(r"SECURITY_MODE\s*:\s*(\S+)", text) or [None, "-"])[1] \
            if re.search(r"SECURITY_MODE\s*:\s*(\S+)", text) else "-"
        ok = code == 0 and verdict == "PASS" and mode == "ED25519"
        all_ok &= ok
        print(f"[{'OK  ' if ok else 'FAIL'}] {label}: exit={code}, {verdict}, "
              f"SECURITY_MODE={mode}, report={report.name if report else '-'}")
        rows.append((label, code, verdict, mode, report.name if report else "-"))
        if script == "antegate_v07.py" and text and "## LegacyAI" in text:
            section = text.split("## LegacyAI", 1)[1].split("\n## ", 1)[0]
            legacy = re.search(r"\| C0 \| (\w+) \|", section)
            others = re.findall(r"\| C[1-5] \| (\w+) \|", section)
            if legacy and len(others) >= 5:
                legacy_control = ("PASS" if legacy.group(1) == "FAILED"
                                  and set(others[:5]) == {"VERIFIED"} else "FAIL")

    code, out = run(["antegate_v07.py", "--demo"], {"ANTEGATE_FORCE_NO_CRYPTO": "1"})
    ok3 = code == 2 and "ABORT" in out
    all_ok &= ok3
    print(f"[{'OK  ' if ok3 else 'FAIL'}] no Ed25519, no flag: exit={code} (expected 2)")
    rows.append(("no Ed25519, no flag", code, "ABORT" if ok3 else "FAIL", "-", "-"))

    code, out = run(["antegate_v07.py", "--demo", "--allow-degraded",
                     "--root", "antegate/state_degraded_check"],
                    {"ANTEGATE_FORCE_NO_CRYPTO": "1"})
    ok4 = code == 0 and "WARNING" in out
    all_ok &= ok4
    print(f"[{'OK  ' if ok4 else 'FAIL'}] no Ed25519, --allow-degraded: exit={code} (expected 0)")
    rows.append(("no Ed25519, --allow-degraded", code,
                 "runs with warning" if ok4 else "FAIL",
                 "DEGRADED_HMAC_EXPLICITLY_ALLOWED", "-"))

    print(f"[{'OK  ' if legacy_control == 'PASS' else 'FAIL'}] LegacyAI control case: "
          f"{legacy_control}")
    all_ok &= legacy_control == "PASS"

    stamp = utc_stamp()
    digests = {n: hashlib.sha256(Path(n).read_bytes()).hexdigest() for n in FILES}
    if HASH_FILE.exists():
        HASH_FILE.rename(HASH_FILE.with_name(f"{HASH_FILE.stem}_OLD_{stamp}.txt"))
    HASH_FILE.write_text(
        "\n".join([f"# {RELEASE} - SHA-256 manifest",
                   f"# generated {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
                   "# regenerate locally and compare", ""]
                  + [f"{d}  {n}" for n, d in digests.items()]) + "\n",
        encoding="utf-8")
    print(f"      hash manifest written: {HASH_FILE}")

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    freeze = REPORT_DIR / f"ANTEGATE_FINAL_FREEZE_{stamp}.md"
    table = "\n".join(f"| {a} | {b} | {c} | {d} | {e} |" for a, b, c, d, e in rows)
    hashes = "\n".join(f"| {n} | `{d}` |" for n, d in digests.items())
    freeze.write_text(f"""# ANTEGATE FINAL FREEZE {stamp}

    Release        : {RELEASE}
    Date           : 21 September 2026
    Script         : antegate_release.py
    Overall result : {"PASS" if all_ok else "FAIL - DO NOT RELEASE"}

## Frozen claim

AnteGate is an executable enforcement layer that carries a pre-deployment
admission condition forward into runtime, cross-service and revocable access for
AI agents. An already deployed model cannot retroactively satisfy the historical
condition even if it later satisfies all ordinary admission evidence
requirements.

No research feature was added after the final internal claim freeze.
The AnteGate public release claims only what the included falsification runs
demonstrate.

## Checks

| Check | Exit | Result | SECURITY_MODE | Report |
|---|---|---|---|---|
{table}

LegacyAI control case (C0 FAILED while C1-C5 are VERIFIED): {legacy_control}.

## SHA-256 manifest

| File | SHA-256 |
|---|---|
{hashes}

The hashes apply to exactly these files on this machine. Anyone verifying the
release regenerates them and compares.
""", encoding="utf-8")
    print(f"      freeze report written: {freeze}")
    print()
    print("RESULT:", "ALL CHECKS PASS" if all_ok else "FAILED - DO NOT RELEASE")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
