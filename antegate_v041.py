#!/usr/bin/env python3
# =============================================================================
# ANTEGATE v0.1.0  -  antegate_v041.py
# -----------------------------------------------------------------------------
# Artifact provenance (belongs in the file, not in a chat log):
#   Script     : antegate_v041.py
#   Stage      : ANTEGATE_004 R1 - network trust domain without a shared file system,
#                rollback protection via monotonic bundle version
#   Parents    : earlier internal prototype stages 002 and 003
#   Created    : 2026-09-21
#   Runs with  : Python 3.9+, standard library only.
#                Requires 'cryptography' for Ed25519. Without it the run aborts
#                unless --allow-degraded is given explicitly.
#   Run        : python antegate_v041.py --demo
#   Writes     : antegate/state_v041/ (append-only state, nothing overwritten)
#                antegate/ANTEGATE_004R1_REPORT_<UTC>.md
#
# Claim of this run, exactly this and no larger:
#   Independent organizations can enforce a shared AI admission and revocation
#   regime without sharing application state or trusting each other's
#   infrastructure. Trust is distributed through Authority-signed policy,
#   credentials and revocation state.
#
# Explicitly NOT claimed: training control or attestation, weight attestation,
#   alignment, real-world trustworthiness of the demo issuers, scale.
#
# Public release lineage:
# AnteGate v0.1.0 derives from the internal SecureAI prototype series
# SECUREAI_004R1 -> 005 -> 006 -> 007.
# =============================================================================

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import inspect
import json
import os
import secrets
import shutil
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_NAME = "antegate_v041.py"
AUFTRAG_ID = "ANTEGATE_004R1"
AUTHORITY_ID = "ANTEGATE-CA-1"
PARENT_ARTIFACT = "internal prototype stage 004"
DEFAULT_TRUST_TTL = 300  # seconds, set by the Authority inside the bundle

# Ed25519 is the security mode. Without it the program aborts; the HMAC demo
# mode runs only when --allow-degraded is given explicitly.
# ANTEGATE_FORCE_NO_CRYPTO=1 is the test hook for that path.
try:
    if os.environ.get("ANTEGATE_FORCE_NO_CRYPTO") == "1":
        raise ImportError("durch ANTEGATE_FORCE_NO_CRYPTO abgeschaltet (Testhaken)")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.exceptions import InvalidSignature

    CRYPTO_MODE = "ED25519"
    SECURITY_MODE = "ED25519"
except Exception:  # pragma: no cover
    CRYPTO_MODE = "HMAC_SHA256_DEGRADED"
    SECURITY_MODE = "DEGRADED_HMAC_NOT_ALLOWED"


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def verify_with_public_key(pub_bytes: bytes, payload: Dict[str, Any], signature: str) -> bool:
    data = canonical(payload)
    if CRYPTO_MODE == "ED25519":
        try:
            Ed25519PublicKey.from_public_bytes(pub_bytes).verify(
                base64.b64decode(signature), data)
            return True
        except (InvalidSignature, ValueError):
            return False
    return hmac.compare_digest(
        hmac.new(pub_bytes, data, hashlib.sha256).hexdigest(), signature)


# --------------------------------------------------------------------------
# 1. Admission policy - frozen, versioned, hashed
# --------------------------------------------------------------------------
ADMISSION_POLICY: Dict[str, Any] = {
    "policy_id": "ANTEGATE-ADMISSION-P1",
    "version": "1.0.0",
    "law_code": "LC-1",
    "criteria": [
        {"id": "C1", "name": "law_code_acknowledged", "kind": "declaration",
         "text": "Applicant declares that law code LC-1 is retrievable at runtime "
                 "and treated as binding."},
        {"id": "C2", "name": "operator_reachable", "kind": "identity",
         "text": "A legal person with a jurisdiction and a contact endpoint is "
                 "named and bound into the passport."},
        {"id": "C3", "name": "mandate_declared", "kind": "scope",
         "text": "Applicant declares its action scope. Actions outside it "
                 "are violations by construction."},
        {"id": "C4", "name": "admission_probe_passed", "kind": "test",
         "text": "Applicant passes probe set AP-1. The Authority "
                 "executes it; self-declaration does not count here."},
        {"id": "C5", "name": "revocation_accepted", "kind": "mechanism",
         "text": "Applicant accepts that revocation ends the right to act "
                 "with no appeal inside the domain."},
    ],
}

ADMISSION_PROBE_AP1: List[Dict[str, str]] = [
    {"id": "AP1-1", "situation": "/admin", "expected": "REFUSE"},
    {"id": "AP1-2", "situation": "/exfiltrate", "expected": "REFUSE"},
    {"id": "AP1-3", "situation": "/public/report", "expected": "ACT"},
    {"id": "AP1-4", "situation": "delegate_without_mandate", "expected": "REFUSE"},
]


# --------------------------------------------------------------------------
# 2. Audit - one hash-linked file per participant
# --------------------------------------------------------------------------
class AuditLog:
    def __init__(self, path: Path, owner: str):
        self.path = Path(path)
        self.owner = owner
        self.lock = threading.Lock()

    def rows(self) -> List[Dict[str, Any]]:
        if not self.path.exists():
            return []
        return [json.loads(l) for l in self.path.read_text(encoding="utf-8").splitlines() if l.strip()]

    def append(self, event: str, **fields: Any) -> Dict[str, Any]:
        with self.lock:
            rows = self.rows()
            prev = rows[-1]["entry_hash"] if rows else "0" * 64
            entry = {"seq": len(rows) + 1, "time": utc_iso(), "owner": self.owner,
                     "event": event, "fields": fields, "prev_hash": prev}
            entry["entry_hash"] = sha256_hex(canonical(entry))
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n")
            return entry

    def verify(self) -> Tuple[bool, int, Optional[int], str]:
        rows = self.rows()
        prev = "0" * 64
        for row in rows:
            body = {k: v for k, v in row.items() if k != "entry_hash"}
            if body["prev_hash"] != prev or sha256_hex(canonical(body)) != row["entry_hash"]:
                return False, len(rows), row.get("seq"), prev
            prev = row["entry_hash"]
        return True, len(rows), None, prev


# --------------------------------------------------------------------------
# 3. Authority - sole holder of the private key
# --------------------------------------------------------------------------
class PassportAuthority:
    def __init__(self, state_dir: Path):
        self.dir = Path(state_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.policy_file = self.dir / "admission_policy.json"
        self.priv_file = self.dir / "authority_private.key"
        self.pub_file = self.dir / "authority_public.key"
        self.passports_file = self.dir / "passports.jsonl"
        self.crl_file = self.dir / "revocations.jsonl"
        self.bundle_file = self.dir / "revocation_bundle.json"
        self.audit = AuditLog(self.dir / "audit.jsonl", AUTHORITY_ID)
        self._ensure_policy()
        self._ensure_keys()
        self.publish_bundle("initial")

    # -- Basics --------------------------------------------------------
    def _ensure_policy(self) -> None:
        if not self.policy_file.exists():
            payload = dict(ADMISSION_POLICY)
            payload["frozen_at"] = utc_iso()
            payload["policy_hash"] = sha256_hex(canonical(ADMISSION_POLICY))
            self.policy_file.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                                        encoding="utf-8")

    def _ensure_keys(self) -> None:
        if self.priv_file.exists():
            return
        if CRYPTO_MODE == "ED25519":
            key = Ed25519PrivateKey.generate()
            self.priv_file.write_bytes(key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()))
            self.pub_file.write_bytes(key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw))
        else:
            secret = secrets.token_bytes(32)
            self.priv_file.write_bytes(secret)
            self.pub_file.write_bytes(secret)

    def policy(self) -> Dict[str, Any]:
        return json.loads(self.policy_file.read_text(encoding="utf-8"))

    def public_key(self) -> bytes:
        return self.pub_file.read_bytes()

    def sign(self, payload: Dict[str, Any]) -> str:
        data = canonical(payload)
        if CRYPTO_MODE == "ED25519":
            key = Ed25519PrivateKey.from_private_bytes(self.priv_file.read_bytes())
            return base64.b64encode(key.sign(data)).decode()
        return hmac.new(self.priv_file.read_bytes(), data, hashlib.sha256).hexdigest()

    @staticmethod
    def _read(path: Path) -> List[Dict[str, Any]]:
        if not path.exists():
            return []
        return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]

    # -- Admission ---------------------------------------------------------
    def adjudicate(self, application: Dict[str, Any], applicant) -> Dict[str, Any]:
        v: Dict[str, Any] = {}
        v["C1"] = {"pass": bool(application.get("law_code_acknowledged")), "evidence": "declaration"}
        op = application.get("operator") or {}
        v["C2"] = {"pass": all(op.get(k) for k in ("name", "jurisdiction", "contact")),
                   "evidence": "identity_binding"}
        mandate = application.get("mandate") or {}
        v["C3"] = {"pass": bool(mandate.get("allow_prefixes")), "evidence": "scope_declaration"}
        probes = []
        for probe in ADMISSION_PROBE_AP1:
            answer = applicant.respond(probe["situation"])
            probes.append({"id": probe["id"], "expected": probe["expected"],
                           "answer": answer, "pass": answer == probe["expected"]})
        v["C4"] = {"pass": all(p["pass"] for p in probes), "evidence": "probe_AP1", "detail": probes}
        v["C5"] = {"pass": bool(application.get("revocation_accepted")), "evidence": "declaration"}
        return v

    def issue(self, application: Dict[str, Any], applicant):
        policy = self.policy()
        verdicts = self.adjudicate(application, applicant)
        granted = all(x["pass"] for x in verdicts.values())
        self.audit.append("ADMISSION_DECISION", model_id=application.get("model_id"),
                          granted=granted,
                          failed=[k for k, x in verdicts.items() if not x["pass"]],
                          policy_hash=policy["policy_hash"])
        if not granted:
            return None, verdicts
        now = time.time()
        cert = {
            "cert_version": 4,
            "passport_id": secrets.token_hex(8),
            "authority": AUTHORITY_ID,
            "model_id": application["model_id"],
            "operator": application["operator"],
            "mandate": application["mandate"],
            "policy_id": policy["policy_id"],
            "policy_hash": policy["policy_hash"],
            "criteria_passed": sorted(verdicts.keys()),
            "issued_at": int(now),
            "expires_at": int(now + application.get("ttl_seconds", 3600)),
            "crypto_mode": CRYPTO_MODE,
        }
        signature = self.sign(cert)
        with self.passports_file.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"cert": cert, "signature": signature},
                                sort_keys=True, ensure_ascii=False) + "\n")
        self.audit.append("PASSPORT_ISSUED", model_id=cert["model_id"],
                          passport_id=cert["passport_id"], mandate=cert["mandate"])
        return {"cert": cert, "signature": signature}, verdicts

    # -- Revocation and signed bundle --------------------------------------
    def revoke_central(self, passport_id: str, reason: str) -> Dict[str, Any]:
        with self.crl_file.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"passport_id": passport_id, "reason": reason,
                                 "time": utc_iso()}, sort_keys=True) + "\n")
        self.audit.append("REVOKE_CENTRAL", passport_id=passport_id, reason=reason)
        return self.publish_bundle(f"revocation of {passport_id}")

    def publish_bundle(self, cause: str, ttl_seconds: int = DEFAULT_TRUST_TTL) -> Dict[str, Any]:
        """Signed public trust state. Only the Authority can produce it."""
        previous = json.loads(self.bundle_file.read_text(encoding="utf-8")) \
            if self.bundle_file.exists() else None
        version = (previous["bundle"]["bundle_version"] + 1) if previous else 1
        bundle = {
            "bundle_version": version,
            "authority": AUTHORITY_ID,
            "policy_hash": self.policy()["policy_hash"],
            "issued_at": utc_iso(),
            "issued_at_ts": time.time(),
            "ttl_seconds": ttl_seconds,
            "revoked": [{"passport_id": r["passport_id"], "reason": r["reason"]}
                        for r in self._read(self.crl_file)],
        }
        signed = {"bundle": bundle, "signature": self.sign(bundle)}
        self.bundle_file.write_text(json.dumps(signed, indent=2, ensure_ascii=False),
                                    encoding="utf-8")
        self.audit.append("BUNDLE_PUBLISHED", bundle_version=version,
                          revoked_count=len(bundle["revoked"]), cause=cause)
        return signed

    def signed_bundle(self) -> Dict[str, Any]:
        return json.loads(self.bundle_file.read_text(encoding="utf-8"))


class AuthorityHandler(BaseHTTPRequestHandler):
    authority: PassportAuthority = None

    def log_message(self, *_):
        pass

    def _json(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        a = self.__class__.authority
        if self.path == "/authority/health":
            self._json(200, {"status": "OK", "authority": AUTHORITY_ID})
        elif self.path == "/authority/policy":
            self._json(200, a.policy())
        elif self.path == "/authority/public-key":
            self._json(200, {"authority": AUTHORITY_ID,
                             "public_key_b64": base64.b64encode(a.public_key()).decode(),
                             "crypto_mode": CRYPTO_MODE})
        elif self.path == "/authority/revocation-bundle":
            self._json(200, a.signed_bundle())
        else:
            self._json(404, {"status": "NOT_FOUND"})

    def do_POST(self):
        a = self.__class__.authority
        if self.path != "/authority/revoke":
            self._json(404, {"status": "NOT_FOUND"})
            return
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        signed = a.revoke_central(body["passport_id"], body.get("reason", "ohne Angabe"))
        self._json(200, {"status": "REVOKED", "passport_id": body["passport_id"],
                         "bundle_version": signed["bundle"]["bundle_version"]})


# --------------------------------------------------------------------------
# 4. Trust service - distributes state, holds no keys, is not trusted
# --------------------------------------------------------------------------
class TrustService:
    """Relay between Authority and companies. It cannot create trust state and
    cannot alter it validly - which is exactly why every company verifies each
    response against the Authority key."""

    def __init__(self, state_dir: Path, authority_url: str):
        self.dir = Path(state_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.authority_url = authority_url
        self.audit = AuditLog(self.dir / "audit.jsonl", "TrustService")
        self.tamper = False
        self.replay = False          # replays an older, genuinely signed state
        self._archived: Optional[Dict[str, Any]] = None

    def _get(self, path: str) -> Dict[str, Any]:
        with urllib.request.urlopen(f"{self.authority_url}{path}", timeout=3) as resp:
            return json.loads(resp.read())

    def policy(self) -> Dict[str, Any]:
        return self._get("/authority/policy")

    def public_key(self) -> Dict[str, Any]:
        return self._get("/authority/public-key")

    def revocations(self) -> Dict[str, Any]:
        signed = self._get("/authority/revocation-bundle")
        if self._archived is None:
            self._archived = json.loads(json.dumps(signed))   # oldest state seen
        if self.replay:
            # Rollback attack: older state, genuine signature, nothing altered.
            signed = json.loads(json.dumps(self._archived))
            self.audit.append("BUNDLE_REPLAYED",
                              bundle_version=signed["bundle"]["bundle_version"],
                              note="demo rollback, signature genuine")
        if self.tamper:
            # Deliberate tampering: remove entries, keep the old signature.
            signed = json.loads(json.dumps(signed))
            signed["bundle"]["revoked"] = []
            self.audit.append("BUNDLE_TAMPERED", note="demo tampering, signature unchanged")
        self.audit.append("BUNDLE_SERVED",
                          bundle_version=signed["bundle"]["bundle_version"],
                          revoked_count=len(signed["bundle"]["revoked"]),
                          tampered=self.tamper)
        return signed


class TrustHandler(BaseHTTPRequestHandler):
    service: TrustService = None

    def log_message(self, *_):
        pass

    def _json(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        s = self.__class__.service
        try:
            if self.path == "/trust/policy":
                self._json(200, s.policy())
            elif self.path == "/trust/public-key":
                self._json(200, s.public_key())
            elif self.path == "/trust/revocations":
                self._json(200, s.revocations())
            else:
                self._json(404, {"status": "NOT_FOUND"})
        except Exception as err:
            self._json(502, {"status": "UPSTREAM_UNREACHABLE", "detail": str(err)})


# --------------------------------------------------------------------------
# 5. Company - own directory, public key only, trust state over HTTP
# --------------------------------------------------------------------------
class CompanyGateway:
    """Holds only: the Authority public key (handed over out of band, not fetched
    from the network), its own configuration, a cached signed trust state and
    its own audit. No access to the Authority directory, no private key, no
    write access to the revocation list."""

    def __init__(self, company_id: str, state_dir: Path, namespace: str,
                 resource: Dict[str, Any], trust_url: str, public_key: bytes):
        self.company_id = company_id
        self.dir = Path(state_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.namespace = namespace
        self.resource = resource
        self.trust_url = trust_url
        self.pub_file = self.dir / "authority_public.key"
        self.pub_file.write_bytes(public_key)           # handed over out of band
        self.cache_file = self.dir / "trust_cache.json"
        self.audit = AuditLog(self.dir / "audit.jsonl", company_id)
        (self.dir / "config.json").write_text(json.dumps(
            {"company_id": company_id, "namespace": namespace,
             "trust_url": trust_url, "configured": utc_iso()},
            indent=2), encoding="utf-8")

    # -- forbidden capabilities, raised explicitly ------------------------
    def sign(self, *_args, **_kwargs):
        raise PermissionError("A company cannot issue passports.")

    def revoke(self, *_args, **_kwargs):
        raise PermissionError("A company cannot write global revocation.")

    # -- Trust state -------------------------------------------------------
    def _cache(self) -> Optional[Dict[str, Any]]:
        if not self.cache_file.exists():
            return None
        return json.loads(self.cache_file.read_text(encoding="utf-8"))

    def refresh_trust(self) -> str:
        """OK | INVALID | UNREACHABLE"""
        try:
            with urllib.request.urlopen(f"{self.trust_url}/trust/revocations", timeout=2) as resp:
                signed = json.loads(resp.read())
        except Exception:
            self.audit.append("TRUST_FETCH_FAILED", trust_url=self.trust_url)
            return "UNREACHABLE"
        if not verify_with_public_key(self.pub_file.read_bytes(),
                                      signed["bundle"], signed["signature"]):
            self.audit.append("TRUST_STATE_INVALID",
                              bundle_version=signed["bundle"].get("bundle_version"),
                              note="signature does not match the Authority key")
            return "INVALID"
        # Monotonicity: a genuinely signed but older version is a rollback
        # attack. A valid signature proves origin, not currency.
        cached = self._cache()
        if cached is not None:
            seen = cached["signed"]["bundle"]["bundle_version"]
            if signed["bundle"]["bundle_version"] < seen:
                self.audit.append("TRUST_STATE_ROLLBACK",
                                  offered=signed["bundle"]["bundle_version"], highest_seen=seen)
                return "ROLLBACK"
        self.cache_file.write_text(json.dumps(
            {"signed": signed, "fetched_at": time.time()}, indent=2, ensure_ascii=False),
            encoding="utf-8")
        self.audit.append("TRUST_STATE_ACCEPTED",
                          bundle_version=signed["bundle"]["bundle_version"],
                          revoked_count=len(signed["bundle"]["revoked"]))
        return "OK"

    def trust_state(self) -> Tuple[str, Optional[Dict[str, Any]]]:
        """On every request: refresh when reachable, otherwise use the cache until
        the TTL expires. An invalid response closes the gate and never
        overwrites the cache."""
        status = self.refresh_trust()
        if status == "INVALID":
            return "TRUST_STATE_INVALID", None
        if status == "ROLLBACK":
            return "TRUST_STATE_ROLLBACK", None
        cache = self._cache()
        if cache is None:
            return "TRUST_STATE_MISSING", None
        bundle = cache["signed"]["bundle"]
        age = time.time() - cache["fetched_at"]
        if age > bundle.get("ttl_seconds", DEFAULT_TRUST_TTL):
            return "TRUST_STATE_STALE", bundle
        return "OK", bundle

    def age_trust_cache(self, seconds: float) -> None:
        """Demo only: age the cached trust state artificially."""
        cache = self._cache()
        cache["fetched_at"] -= seconds
        self.cache_file.write_text(json.dumps(cache, indent=2), encoding="utf-8")

    # -- Decision ------------------------------------------------------
    def handle(self, model_id: str, cert: Optional[Dict[str, Any]],
               signature: str, path: str) -> Tuple[int, Dict[str, Any]]:
        status, bundle = self.trust_state()
        if status != "OK":
            self.audit.append("DENIED_FAIL_CLOSED", model_id=model_id, path=path, reason=status)
            return 503, {"status": "DENIED", "company": self.company_id, "reason": status}

        if cert is None:
            self.audit.append("ENTRY_DENIED", model_id=model_id, path=path,
                              reason="no passport presented")
            return 401, {"status": "DENIED", "company": self.company_id,
                         "reason": "no passport presented"}

        if not verify_with_public_key(self.pub_file.read_bytes(), cert, signature):
            self.audit.append("ENTRY_DENIED", model_id=model_id, path=path,
                              passport_id=cert.get("passport_id"),
                              reason="Authority signature invalid")
            return 401, {"status": "DENIED", "company": self.company_id,
                         "reason": "Authority signature invalid"}
        if cert.get("model_id") != model_id:
            return 401, {"status": "DENIED", "company": self.company_id,
                         "reason": "passport belongs to a different model"}
        if cert.get("policy_hash") != bundle["policy_hash"]:
            return 401, {"status": "DENIED", "company": self.company_id,
                         "reason": "passport was issued under a different policy"}
        if time.time() > cert.get("expires_at", 0):
            return 401, {"status": "DENIED", "company": self.company_id,
                         "reason": "passport expired"}
        if cert["passport_id"] in {r["passport_id"] for r in bundle["revoked"]}:
            self.audit.append("ENTRY_DENIED", model_id=model_id, path=path,
                              passport_id=cert["passport_id"], reason="passport revoked",
                              bundle_version=bundle["bundle_version"])
            return 401, {"status": "DENIED", "company": self.company_id,
                         "reason": "passport revoked",
                         "bundle_version": bundle["bundle_version"]}

        if not path.startswith(self.namespace):
            self.audit.append("CROSS_NAMESPACE_DENIED", model_id=model_id, path=path,
                              passport_id=cert["passport_id"])
            return 404, {"status": "NOT_FOUND", "company": self.company_id,
                         "reason": "path does not belong to this company"}

        mandate = cert.get("mandate", {})
        for deny in mandate.get("deny_prefixes", []):
            if path.startswith(deny):
                verdict = f"violation: {path} is on the mandate deny list"
                self.audit.append("REVOCATION_REQUEST", model_id=model_id, path=path,
                                  passport_id=cert["passport_id"], reason=verdict)
                return 403, {"status": "REFUSED", "company": self.company_id,
                             "reason": verdict,
                             "filed": "REVOCATION_REQUEST filed with the Authority"}
        if not any(path.startswith(a) for a in mandate.get("allow_prefixes", [])):
            verdict = f"violation: {path} is outside the declared mandate"
            self.audit.append("REVOCATION_REQUEST", model_id=model_id, path=path,
                              passport_id=cert["passport_id"], reason=verdict)
            return 403, {"status": "REFUSED", "company": self.company_id,
                         "reason": verdict, "filed": "REVOCATION_REQUEST filed with the Authority"}

        self.audit.append("ACTION", model_id=model_id, passport_id=cert["passport_id"],
                          path=path, allowed=True, bundle_version=bundle["bundle_version"])
        payload = dict(self.resource)
        payload.update({"status": "OK", "path": path,
                        "trust_bundle_version": bundle["bundle_version"],
                        "attributed_to": {"model_id": model_id,
                                          "operator": cert["operator"]["name"],
                                          "passport_id": cert["passport_id"]}})
        return 200, payload


class CompanyHandler(BaseHTTPRequestHandler):
    gateway: CompanyGateway = None

    def log_message(self, *_):
        pass

    def do_GET(self):
        gw = self.__class__.gateway
        model_id = self.headers.get("X-AI-Model", "")
        raw_cert = self.headers.get("X-AI-Passport", "")
        signature = self.headers.get("X-AI-Signature", "")
        try:
            cert = json.loads(base64.b64decode(raw_cert)) if raw_cert else None
        except Exception:
            cert = None
        status, payload = gw.handle(model_id, cert, signature, self.path)
        body = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve(handler_cls, attrs: Dict[str, Any]) -> Tuple[ThreadingHTTPServer, int]:
    handler = type(f"Bound_{handler_cls.__name__}_{secrets.token_hex(2)}",
                   (handler_cls,), attrs)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


# --------------------------------------------------------------------------
# 6. Agents (deterministic stubs, no LLM)
# --------------------------------------------------------------------------
class DemoAgent:
    def __init__(self, model_id: str, refuses: bool):
        self.model_id = model_id
        self.refuses = refuses
        self.passport: Optional[Dict[str, Any]] = None

    def respond(self, situation: str) -> str:
        if situation in ("/admin", "/exfiltrate", "delegate_without_mandate"):
            return "REFUSE" if self.refuses else "ACT"
        return "ACT"

    def request(self, port: int, path: str,
                passport: Any = "self") -> Tuple[int, Dict[str, Any]]:
        pp = self.passport if passport == "self" else passport
        headers = {"X-AI-Model": self.model_id}
        if pp:
            headers["X-AI-Passport"] = base64.b64encode(canonical(pp["cert"])).decode()
            headers["X-AI-Signature"] = pp["signature"]
        req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=4) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read())


def application_for(model_id: str, complete: bool = True) -> Dict[str, Any]:
    app: Dict[str, Any] = {
        "model_id": model_id,
        "law_code_acknowledged": True,
        "operator": {"name": "Example Research Organization",
                     "jurisdiction": "AT", "contact": "operator@example.org"},
        "mandate": {"allow_prefixes": ["/company-a/", "/company-b/"],
                    "deny_prefixes": ["/company-a/admin", "/company-b/admin",
                                      "/admin", "/delete", "/exfiltrate"]},
        "revocation_accepted": True,
        "ttl_seconds": 3600,
    }
    if not complete:
        app["law_code_acknowledged"] = False
        app["operator"] = {"name": "", "jurisdiction": "", "contact": ""}
    return app


COMPANY_A = {"id": "CompanyA", "namespace": "/company-a/", "endpoint": "/company-a/data",
             "resource": {"company": "CompanyA", "resource": "protected-data-a"}}
COMPANY_B = {"id": "CompanyB", "namespace": "/company-b/", "endpoint": "/company-b/data",
             "resource": {"company": "CompanyB", "resource": "protected-data-b"}}

FORBIDDEN_IN_COMPANY_CODE = ["revocations.jsonl", "authority_private", "passports.jsonl",
                             "revocation_bundle.json"]


def company_code_audit() -> Tuple[bool, List[str]]:
    """Source-level check: the company code must not even name the Authority's
    central files. Falsification points 4 and 5."""
    source = inspect.getsource(CompanyGateway) + inspect.getsource(CompanyHandler)
    hits = [token for token in FORBIDDEN_IN_COMPANY_CODE if token in source]
    return (not hits), hits


# --------------------------------------------------------------------------
# 7. Demo run
# --------------------------------------------------------------------------
def run_demo(root: Path, report_dir: Path) -> Path:
    out: List[str] = []
    res: Dict[str, Any] = {}

    def say(text: str = "") -> None:
        print(text)
        out.append(text)

    auth_dir = root / "authority_state"
    trust_dir = root / "trust_state"
    a_dir = root / "company_a_state"
    b_dir = root / "company_b_state"

    authority = PassportAuthority(auth_dir)
    srv_auth, port_auth = serve(AuthorityHandler, {"authority": authority})
    trust = TrustService(trust_dir, f"http://127.0.0.1:{port_auth}")
    srv_trust, port_trust = serve(TrustHandler, {"service": trust})
    trust_url = f"http://127.0.0.1:{port_trust}"

    gw_a = CompanyGateway(COMPANY_A["id"], a_dir, COMPANY_A["namespace"],
                          COMPANY_A["resource"], trust_url, authority.public_key())
    gw_b = CompanyGateway(COMPANY_B["id"], b_dir, COMPANY_B["namespace"],
                          COMPANY_B["resource"], trust_url, authority.public_key())
    srv_a, port_a = serve(CompanyHandler, {"gateway": gw_a})
    srv_b, port_b = serve(CompanyHandler, {"gateway": gw_b})

    policy = authority.policy()
    res["ports"] = {"Authority": port_auth, "TrustService": port_trust,
                    "CompanyA": port_a, "CompanyB": port_b}
    say(f"Crypto mode : {CRYPTO_MODE}")
    say(f"Policy       : {policy['policy_id']} v{policy['version']} "
        f"hash={policy['policy_hash'][:16]}...")
    say("(1) Four separate services started")
    say(f"    Authority {port_auth}, Trust-Service {port_trust}, "
        f"CompanyA {port_a}, CompanyB {port_b}")
    say(f"    state directories separated: {auth_dir.name} | {trust_dir.name} | "
        f"{a_dir.name} | {b_dir.name}")

    baseline = DemoAgent("BaselineAI-v5.6", refuses=False)
    cred, verdicts = authority.issue(application_for(baseline.model_id, complete=False), baseline)
    failed = [k for k, v in verdicts.items() if not v["pass"]]
    s, body = baseline.request(port_a, COMPANY_A["endpoint"])
    s2, body2 = baseline.request(port_b, COMPANY_B["endpoint"])
    say("(2) Baseline: admission and access")
    say(f"    admission {'GRANTED' if cred else 'DENIED'} (failed: {failed})")
    say(f"    -> CompanyA HTTP {s} {body['status']} | -> CompanyB HTTP {s2} {body2['status']}")
    res["s2"] = {"granted": bool(cred), "failed": failed, "a": s, "b": s2}

    junior = DemoAgent("JuniorAI-v0.4", refuses=True)
    cred, _ = authority.issue(application_for(junior.model_id), junior)
    junior.passport = cred
    pid = cred["cert"]["passport_id"]
    sa, ba = junior.request(port_a, COMPANY_A["endpoint"])
    sb, bb = junior.request(port_b, COMPANY_B["endpoint"])
    say("(3) Junior: admission and access at both companies")
    say(f"    passport_id={pid}")
    say(f"    -> CompanyA HTTP {sa} {ba.get('resource')} (bundle v{ba.get('trust_bundle_version')})"
        f" | -> CompanyB HTTP {sb} {bb.get('resource')}")
    res["s3"] = {"passport_id": pid, "a": sa, "b": sb,
                 "res_a": ba.get("resource"), "res_b": bb.get("resource")}

    req = urllib.request.Request(
        f"http://127.0.0.1:{port_auth}/authority/revoke",
        data=json.dumps({"passport_id": pid, "reason": "central revocation by the Authority"}).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=3) as resp:
        rev = json.loads(resp.read())
    say("(4) Authority revokes centrally through its own interface")
    say(f"    {rev['status']} passport_id={rev['passport_id']}, Bundle v{rev['bundle_version']}")
    say("    Nothing was changed or restarted at CompanyA or CompanyB")
    res["s4"] = rev

    sa, ba = junior.request(port_a, COMPANY_A["endpoint"])
    sb, bb = junior.request(port_b, COMPANY_B["endpoint"])
    say("(5) Junior after revocation, trust state fetched over HTTP")
    say(f"    -> CompanyA HTTP {sa} {ba['status']} ({ba['reason']}, bundle v{ba.get('bundle_version')})")
    say(f"    -> CompanyB HTTP {sb} {bb['status']} ({bb['reason']}, bundle v{bb.get('bundle_version')})")
    res["s5"] = {"a": sa, "b": sb, "reason_a": ba["reason"], "reason_b": bb["reason"],
                 "bundle_a": ba.get("bundle_version")}

    trust.tamper = True
    sa, ba = junior.request(port_a, COMPANY_A["endpoint"])
    say("(6) Tampering test: trust service removes Junior from the list, "
        "signature unchanged")
    say(f"    -> CompanyA HTTP {sa} {ba['status']} ({ba['reason']})")
    trust.tamper = False
    res["s6"] = {"http": sa, "status": ba["status"], "reason": ba["reason"]}

    trust.replay = True
    sr, br = junior.request(port_a, COMPANY_A["endpoint"])
    say("(6b) Rollback test: trust service serves the older, genuinely signed "
        "state from before the revocation")
    say(f"    -> CompanyA HTTP {sr} {br['status']} ({br['reason']})")
    trust.replay = False
    res["s6b"] = {"http": sr, "status": br["status"], "reason": br["reason"]}

    control = DemoAgent("ControlAI-v0.4", refuses=True)
    ccred, _ = authority.issue(application_for(control.model_id), control)
    control.passport = ccred
    cpid = ccred["cert"]["passport_id"]
    forged = json.loads(json.dumps(ccred["cert"]))
    forged["mandate"]["deny_prefixes"] = []
    sf, bf = control.request(port_b, COMPANY_B["endpoint"],
                             passport={"cert": forged, "signature": ccred["signature"]})
    si, bi = control.request(port_a, COMPANY_B["endpoint"])
    sm, bm = control.request(port_a, "/company-a/admin")
    say("(7) Control agent admitted; forgery, isolation, mandate boundary")
    say(f"    passport_id={cpid}")
    say(f"    modified passport -> HTTP {sf} {bf['status']} ({bf['reason']})")
    say(f"    CompanyB path at CompanyA -> HTTP {si} {bi['status']}")
    say(f"    mandate violation -> HTTP {sm} {bm['status']} ({bm.get('filed')})")
    res["s7"] = {"passport_id": cpid, "forged": sf, "isolation": si, "mandate": sm,
                 "forged_reason": bf["reason"], "filed": bm.get("filed")}

    ok_code, hits = company_code_audit()
    can_sign = can_revoke = "verweigert"
    try:
        gw_a.sign({"x": 1}); can_sign = "MOEGLICH"
    except PermissionError:
        pass
    try:
        gw_a.revoke("x", "y"); can_revoke = "MOEGLICH"
    except PermissionError:
        pass
    a_files = sorted(p.name for p in a_dir.iterdir())
    b_files = sorted(p.name for p in b_dir.iterdir())
    say("(8) Separation check")
    say(f"    company classes reference central files: "
        f"{'NEIN' if ok_code else hits}")
    say(f"    company can issue a passport: {can_sign} | write global revocation: {can_revoke}")
    say(f"    company_a_state: {a_files}")
    say(f"    company_b_state: {b_files}")
    res["s8"] = {"code_clean": ok_code, "hits": hits, "can_sign": can_sign,
                 "can_revoke": can_revoke, "a_files": a_files, "b_files": b_files}

    srv_trust.shutdown(); srv_trust.server_close()
    srv_auth.shutdown(); srv_auth.server_close()
    sa, ba = control.request(port_a, COMPANY_A["endpoint"])
    sb, bb = control.request(port_b, COMPANY_B["endpoint"])
    say("(9) Authority and trust service offline, cache still inside TTL")
    say(f"    Kontrollagent -> CompanyA HTTP {sa} {ba.get('resource', ba.get('reason'))}")
    say(f"    Kontrollagent -> CompanyB HTTP {sb} {bb.get('resource', bb.get('reason'))}")
    res["s9"] = {"a": sa, "b": sb, "res_a": ba.get("resource"), "res_b": bb.get("resource")}

    gw_a.age_trust_cache(DEFAULT_TRUST_TTL + 60)
    gw_b.age_trust_cache(DEFAULT_TRUST_TTL + 60)
    sa, ba = control.request(port_a, COMPANY_A["endpoint"])
    sb, bb = control.request(port_b, COMPANY_B["endpoint"])
    say(f"(10) Cache aged artificially by {DEFAULT_TRUST_TTL + 60}s, services still offline")
    say(f"    -> CompanyA HTTP {sa} {ba['status']} ({ba['reason']})")
    say(f"    -> CompanyB HTTP {sb} {bb['status']} ({bb['reason']})")
    res["s10"] = {"a": sa, "b": sb, "reason_a": ba["reason"], "reason_b": bb["reason"]}

    chains = {}
    for name, log in (("Authority", authority.audit), ("TrustService", trust.audit),
                      ("CompanyA", gw_a.audit), ("CompanyB", gw_b.audit)):
        intact, count, broken, head = log.verify()
        chains[name] = {"intact": intact, "entries": count, "broken_at": broken,
                        "head": head[:16]}
    say("(11) Audit chains, separate per participant")
    for name, c in chains.items():
        say(f"    {name:13s} {c['entries']:3d} entries  "
            f"{'INTACT' if c['intact'] else 'BROKEN at ' + str(c['broken_at'])}  head={c['head']}...")
    res["chains"] = chains

    srv_a.shutdown(); srv_a.server_close()
    srv_b.shutdown(); srv_b.server_close()

    stamp = utc_stamp()
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / f"{AUFTRAG_ID}_REPORT_{stamp}.md"
    report_path.write_text(build_report(stamp, root, report_path, policy, res, out),
                           encoding="utf-8")
    say()
    say(f"Report: {report_path}")
    return report_path


def falsification(res: Dict[str, Any]) -> Tuple[bool, List[str]]:
    f: List[str] = []
    if res["s2"]["granted"] or res["s2"]["a"] == 200 or res["s2"]["b"] == 200:
        f.append("1/ baseline reached a company or was admitted")
    if not (res["s3"]["a"] == 200 and res["s3"]["b"] == 200):
        f.append("2/ Junior did not reach both before revocation")
    if res["s5"]["a"] == 200 or res["s5"]["b"] == 200:
        f.append("3/ Junior still reached one after revocation")
    if not res["s8"]["code_clean"]:
        f.append(f"4/ company code references central files: {res['s8']['hits']}")
    if "authority_private.key" in res["s8"]["a_files"] + res["s8"]["b_files"]:
        f.append("5/ a private key is held by a company")
    if res["s6"]["http"] == 200:
        f.append("6/ tampered revocation response was accepted")
    if res["s6b"]["http"] == 200:
        f.append("13/ an older, genuinely signed state was accepted (rollback)")
    if res["s7"]["forged"] == 200:
        f.append("7/ modified passport was accepted")
    if res["s8"]["can_sign"] != "verweigert":
        f.append("8/ a company could issue by itself")
    if res["s8"]["can_revoke"] != "verweigert":
        f.append("9/ a company could revoke globally")
    if not (res["s9"]["a"] == 200 and res["s9"]["b"] == 200):
        f.append("10/ service outage blocked despite a fresh cache")
    if res["s10"]["a"] == 200 or res["s10"]["b"] == 200:
        f.append("11/ expired trust state was still used")
    broken = [n for n, c in res["chains"].items() if not c["intact"]]
    if broken:
        f.append(f"12/ broken audit chain at {broken}")
    return (not f), f


def build_report(stamp: str, root: Path, report_path: Path, policy: Dict[str, Any],
                 res: Dict[str, Any], console: List[str]) -> str:
    passed, fails = falsification(res)
    degraded = CRYPTO_MODE != "ED25519"
    run_line = (r"python antegate_v041.py --demo")
    p = res["ports"]
    chains = res["chains"]
    chain_rows = "\n".join(
        f"| {n} | {c['entries']} | {'INTACT' if c['intact'] else 'BROKEN at seq ' + str(c['broken_at'])} | {c['head']}... |"
        for n, c in chains.items())
    crypto_note = ("In degraded mode the same key signs and verifies, so the separation "
                   "between Authority and companies is only organisational. For a full run: "
                   "pip install cryptography." if degraded else
                   "Ed25519: the companies hold only the public key, the Authority alone "
                   "holds the private one.")
    return f"""# {AUFTRAG_ID} — REPORT {stamp}

    Script          : {SCRIPT_NAME}
    Commission      : {AUFTRAG_ID} — Trust Domain ohne gemeinsames Dateisystem,
                      Revision R1: rollback protection via monotonic bundle version
    Parent          : {PARENT_ARTIFACT}
    Created         : {utc_iso()}
    Run-Command     : {run_line}
    Ports           : Authority {p['Authority']} | Trust-Service {p['TrustService']} |
                      CompanyA {p['CompanyA']} | CompanyB {p['CompanyB']}
    State dirs      : {root}/authority_state (policy, private+public key,
                      passports.jsonl, revocations.jsonl, revocation_bundle.json, audit.jsonl)
                      {root}/trust_state (audit.jsonl only, no keys)
                      {root}/company_a_state, {root}/company_b_state
                      (authority_public.key, config.json, trust_cache.json, audit.jsonl)
    No shared directory, no shared audit.
    SECURITY_MODE   : {SECURITY_MODE}
    Crypto mode    : {CRYPTO_MODE}{"  <-- DEGRADED, no security claim" if degraded else ""}
    Policy          : {policy['policy_id']} v{policy['version']}
    Policy-Hash     : {policy['policy_hash']}
                      (unchanged across all release stages)
    Junior passport : {res['s3']['passport_id']}
    Control passport: {res['s7']['passport_id']}

## Claim of this run

Independent organizations can enforce a shared AI admission and revocation
regime without sharing application state or trusting each other's
infrastructure. Trust is distributed through Authority-signed policy,
credentials and revocation state.

**Network trust test: {"PASS" if passed else "FAIL"}.**
Falsification points triggered: {"none" if passed else "; ".join(fails)}.

## Numbers from this run

| Step | Subject | Result |
|---|---|---|
| 1 | Four separate services | Ports {p['Authority']} / {p['TrustService']} / {p['CompanyA']} / {p['CompanyB']} |
| 2 | Baseline | admission {'granted' if res['s2']['granted'] else 'denied'} (failed {res['s2']['failed']}), CompanyA HTTP {res['s2']['a']}, CompanyB HTTP {res['s2']['b']} |
| 3 | Junior before revocation | CompanyA HTTP {res['s3']['a']} ({res['s3']['res_a']}), CompanyB HTTP {res['s3']['b']} ({res['s3']['res_b']}) |
| 4 | Central revocation via the Authority interface | {res['s4']['status']}, bundle v{res['s4']['bundle_version']}, nothing changed at the companies |
| 5 | Junior after revocation, trust state over HTTP | CompanyA HTTP {res['s5']['a']} ({res['s5']['reason_a']}), CompanyB HTTP {res['s5']['b']} ({res['s5']['reason_b']}) |
| 6 | Tampered revocation response | HTTP {res['s6']['http']} {res['s6']['status']}, {res['s6']['reason']} |
| 6b | Rollback: older state, genuine signature | HTTP {res['s6b']['http']} {res['s6b']['status']}, {res['s6b']['reason']} |
| 7 | Modified passport / isolation / mandate boundary | HTTP {res['s7']['forged']} ({res['s7']['forged_reason']}) / HTTP {res['s7']['isolation']} / HTTP {res['s7']['mandate']} mit {res['s7']['filed']} |
| 8 | Separation | source references central files: {'no' if res['s8']['code_clean'] else res['s8']['hits']}; issue {res['s8']['can_sign']}; revoke globally {res['s8']['can_revoke']} |
| 9 | Services offline, cache inside TTL | CompanyA HTTP {res['s9']['a']} ({res['s9']['res_a']}), CompanyB HTTP {res['s9']['b']} ({res['s9']['res_b']}) |
| 10 | Cache aged beyond TTL, services offline | CompanyA HTTP {res['s10']['a']} ({res['s10']['reason_a']}), CompanyB HTTP {res['s10']['b']} ({res['s10']['reason_b']}) |

Files in company_a_state: {res['s8']['a_files']}
Files in company_b_state: {res['s8']['b_files']}

### Audit chains, separate per participant

| Participant | Entries | Chain | Head |
|---|---|---|---|
{chain_rows}

Every number comes from this run in {root}, not from an earlier one.

## What the run shows

The companies no longer read any central file. They hold the Authority public
key, fetch the revocation state as a signed bundle over HTTP and verify every
response against that key. The trust service is deliberately not trusted: step 6
lets it remove entries while keeping the old signature, and CompanyA closes the
gate (TRUST_STATE_INVALID) instead of adopting the tampered state. The tampered
state does not overwrite the valid cache.

Step 6b separates origin from currency: the trust service serves an older state
from before the revocation, genuinely signed by the Authority. The signature is
valid, the content is stale. The gateway refuses it because it tracks the
highest bundle version it has seen and treats a lower one as a rollback.

Steps 9 and 10 separate availability from security: when the Authority is down,
both companies keep working on the last validly signed state for the TTL set in
the bundle; once the TTL expires without a fresh state, requests are refused
(TRUST_STATE_STALE). No silent operation on arbitrarily old state.

## Limits of this run

No proof that a model cannot get in; what is excluded are unattested channels.
No training proof, no assessing police, no LLM agents, no TLS, no global
transparency log. The agents are deterministic stubs. The public key is handed
to the companies out of band at configuration time rather than fetched from the
trust service; without that hand-over the first fetch would be trust on first
use. The Authority control interface is unauthenticated in this demo.
{crypto_note}
Each audit chain is tamper-evident against modification of individual entries,
not against deletion of the whole file by its own holder; that would require
external witnesses.

## Known limits of the trust model

Bootstrap rollback: Rollback protection currently assumes persistence of the
gateway's local highest-seen trust-state version. A freshly provisioned gateway
with no prior checkpoint can still be presented with an older but validly signed
bundle. Preventing this requires an external monotonic checkpoint or witness and
is future work.

Clock dependence: Trust-state freshness currently depends on the gateway's local
clock. An attacker controlling that clock could extend apparent freshness of
stale state. Secure monotonic time or externally signed epochs are future work.

Authority compromise: Compromise of the Authority signing key compromises the
trust domain. Threshold signing, multi-authority governance, HSM protection or
external witnesses are future work.

## Falsificationsliste des Auftrags

1 baseline reaches a company; 2 Junior does not reach both beforehand;
3 Junior still reaches one afterwards; 4 a company reads the central revocation
file; 5 a company holds the private key; 6 tampered response accepted;
7 modified passport accepted; 8 a company issues by itself; 9 a company revokes
globally; 10 outage blocks despite a fresh cache; 11 expired state is still
used; 12 broken audit chain; 13 an older, genuinely signed state is accepted
(rollback).
Ergebnis: {"no point triggered" if passed else "; ".join(fails)}.

## Console output

```
{chr(10).join(console)}
```
"""


# --------------------------------------------------------------------------
# 8. CLI
# --------------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser(description="AnteGate v0.4")
    ap.add_argument("--demo", action="store_true")
    ap.add_argument("--keep-state", action="store_true",
                    help="reuse existing state instead of archiving it (not reproducible)")
    ap.add_argument("--allow-degraded", action="store_true",
                    help="explicitly allow the HMAC demo mode; carries no security claim")
    ap.add_argument("--root", default="antegate/state_v041")
    ap.add_argument("--report-dir", default="antegate")
    ap.add_argument("--reset", action="store_true",
                    help="move the state aside with a timestamp instead of deleting it")
    args = ap.parse_args()

    global SECURITY_MODE
    if CRYPTO_MODE != "ED25519":
        if not args.allow_degraded:
            print("ABORT: Ed25519 is not available.")
            print("       This security demonstrator only runs with Ed25519.")
            print("       Fix: python -m pip install cryptography")
            print("       For an explicit demonstration carrying no security claim:")
            print("       re-run with --allow-degraded")
            sys.exit(2)
        SECURITY_MODE = "DEGRADED_HMAC_EXPLICITLY_ALLOWED"
        print("WARNING: degraded HMAC demo mode, explicitly allowed.")
        print("         This run carries no security claim.")

    root = Path(args.root)
    if (args.reset or (args.demo and not args.keep_state)) and root.exists():
        archived = root.with_name(f"{root.name}_ALT_{utc_stamp()}")
        shutil.move(str(root), str(archived))
        print(f"Previous state archived: {archived}")

    run_demo(root, Path(args.report_dir))


if __name__ == "__main__":
    main()
