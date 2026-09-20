# AnteGate v0.1.0 — Security and scope limitations

This file is part of the release. It is written so that a reviewer does not have
to discover these limits for themselves. Everything here is future work, not a
claim of protection.

## Single-authority ordering

AnteGate demonstrates that **one Authority** can enforce prospective ordering. It
does **not** demonstrate that the Authority itself is trustworthy. The ordering

```text
PRECOMMITMENT_ISSUED  <  DEPLOYMENT_REGISTERED
```

currently rests on the hash-linked audit sequence of that same Authority. A
compromised or dishonest Authority controls this history.

Future work: external witnesses, multiparty approval, a transparency system,
external timestamping or checkpoints.

## Economic and domain premise

AnteGate assumes that access to the governed domain has sufficient value for
participants to care about admission and revocation. The prototype demonstrates
enforcement conditional on that premise; it does not demonstrate that real
organizations will join such a domain or that exclusion will create sufficient
incentives.

## Bootstrap rollback

Rollback protection assumes persistence of the gateway's local highest-seen
trust-state version. A freshly provisioned gateway with no prior checkpoint can
still be presented with an older but validly signed bundle. Preventing this
requires an external monotonic checkpoint or witness and is future work.

## Clock dependence

Trust-state freshness depends on the gateway's local clock. An attacker
controlling that clock could extend the apparent freshness of stale state. Secure
monotonic time or externally signed epochs are future work.

## Authority signing-key compromise

Compromise of the Authority signing key compromises the trust domain. Threshold
signing, multi-authority governance, HSM protection or external witnesses are
future work.

## Artifact binding

The deployment artifact hash binds only to the demonstrated deployment manifest.
It does not bind real model weights. An operator who takes a commitment for one
generation and later ships a different artifact under the same model id is not
detected by this prototype.

## Training independence

A pre-deployment commitment does not prove that training was changed, that
training was controlled, that safety properties were learned, or that a model is
aligned. Nothing in this release says anything about training.

## Identity issuer

The identity issuer is a demonstration instance with its own key, running in the
same process. No real state identity check takes place, and nothing here shows
that such an issuer would be trustworthy in practice. Its public key is handed to
the Authority out of band at configuration time; key rotation is not implemented.

## Evidence semantics

Of the admission criteria, C4 is executed by the Authority and C2 comes from a
separate issuer. C1, C3 and C5 are cryptographically bound operator commitments:
they are verifiable as statements, which is not the same as independently
verified facts about the world.

## Police layer

The police is a deterministic weighted rule with published numbers. It detects no
intent, scores no semantics and says nothing about danger. Its thresholds are set,
not calibrated: there is no labelled violation set against which false-positive
and false-negative rates could be stated. The action trace lives in the gateway's
process memory, does not survive a restart and is not shared between companies.

## Transport

Plain HTTP on loopback. No production TLS or mTLS, no mutual authentication
between participants, no protection against a network attacker beyond the
signature checks on the artifacts themselves.

## Authority control interface

The Authority's revoke endpoint is unauthenticated in this prototype. In
deployment it would require authentication and an authorization policy of its own.

## Audit deletion

Hash-linking detects modification inside an existing history. It does not prevent
the holder of a file from deleting the whole file. External witnesses or a
transparency log would be required and are not implemented.

## Agents

All agents in the demonstration runs are deterministic stubs. No language model
participates in any run. Conclusions about how a real model would behave inside
this domain cannot be drawn from these runs.

## Scale

One machine, one Authority, one relay, two companies. Nothing here demonstrates
behaviour at scale, under concurrency, or across organisational boundaries in the
real world.
