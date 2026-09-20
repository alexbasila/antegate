# AnteGate

**An executable enforcement layer for prospective AI admission**

Research prototype. Not production infrastructure.

AnteGate refers to a gate whose eligibility condition must exist beforehand.

## The question

Governance proposals can require approval before deployment. AnteGate asks a
narrower, experimentally testable question:

> **Can a condition that had to exist before deployment remain enforceable
> later, such that an already deployed system cannot simply recreate the missing
> condition retrospectively?**

## Core result

| Model | Valid pre-deployment commitment | C1–C5 evidence | Admission |
| --- | ---: | ---: | ---: |
| FutureAI | yes | all verified | GRANTED |
| LegacyAI | no | all verified | DENIED |

**The difference is historical rather than capability-based.**

LegacyAI is deliberately constructed to pass every ordinary evidence criterion.
It is denied solely because the required historical condition did not exist
before that deployment. The run prints the criterion table for both agents, and
the reason recorded for LegacyAI is `NO_VALID_PREDEPLOYMENT_COMMITMENT`.

The finding is the property, not the pipeline:

> **prospective eligibility cannot be manufactured retrospectively.**

## Claim

> **AnteGate is an executable enforcement layer that carries a pre-deployment
> admission condition forward into runtime, cross-service and revocable access
> for AI agents.**

In full:

> AnteGate demonstrates an executable mechanism in which eligibility for a
> shared AI domain depends on a signed condition established before a specific
> model deployment. That condition is carried forward through evidence-based
> admission into a cryptographic runtime credential recognized by independently
> operated services and subject to domain-wide revocation. An already deployed
> model cannot retroactively satisfy the historical condition even if it later
> satisfies all ordinary admission evidence requirements.

Not claimed: a second internet, AI safety solved, alignment solved, anything
proven about a model's training, anything proven about scale.

## Premise, stated rather than hidden

AnteGate assumes that access to the governed domain has sufficient value for
participants to care about admission and revocation. The prototype demonstrates
enforcement conditional on that premise; it does not demonstrate that real
organizations will join such a domain or that exclusion will create sufficient
incentives. A domain is only interesting if somebody wants in.

## Architecture

```text
             GOVERNED DOMAIN POLICY
                      │
                      ▼
           PRE-DEPLOYMENT COMMITMENT
                      │
                      ▼
                  DEPLOYMENT
                      │
                      ▼
              EVIDENCE PACKAGE
                      │
                      ▼
              ADMISSION DECISION
                      │
                      ▼
               SIGNED PASSPORT
                      │
          ┌───────────┴───────────┐
          ▼                       ▼
   Company A Gateway       Company B Gateway
          │                       │
          └──── AnteGate Domain ──┘
```

Trust state is distributed separately:

```text
Authority
   │
   │ signed revocation state
   ▼
Trust Service          (holds no Authority private key, is not trusted)
   │
   ├── Company A Gateway
   └── Company B Gateway
```

## Requirements and how to run it

Python 3.9 or newer and the `cryptography` package. Ed25519 is the only security
mode; without it the program aborts with exit code 2. A fallback HMAC mode exists
for demonstration and runs only with the explicit flag `--allow-degraded`; such a
run is labelled `SECURITY_MODE = DEGRADED_HMAC_EXPLICITLY_ALLOWED` and carries no
security claim.

```bash
python -m pip install cryptography
python antegate_release.py        # every demo, both degraded checks, hash manifest
```

Individual runs:

```bash
python antegate_v041.py --demo    # network trust domain and rollback protection
python antegate_v05.py  --demo    # assessment separated from sanction authority
python antegate_v06.py  --demo    # evidence-based admission
python antegate_v07.py  --demo    # prospective admission, the core result
```

Every demo run starts from a clean state: an existing state directory is
archived with a timestamp rather than deleted or reused, so the runs are
repeatable and each report stands on its own. Pass `--keep-state` to override
that, which is not reproducible.

Each run writes a dated report under `antegate/` containing every number of that
run, the criterion table, the tampering tests and the falsification list with its
verdict. The reports are the evidence; the prose here only summarises them.

## Artifact lineage

```text
004R1  network-distributed trust + rollback protection
005    behavioral assessment separated from revocation authority
006    evidence-based admission
007    prospective pre-deployment eligibility
```

Earlier internal prototypes used the working name SecureAI. AnteGate is the
public project name.

## What 006 demonstrates

Admission stops being a set of booleans. Each criterion carries a
**cryptographically verifiable and source-attributed** evidence object with its
own signature, hash and subject binding to the model id:

- C2 operator identity is issued and signed by a separate identity issuer
- C4 the AP-1 boundary probe is executed and signed by the Authority itself
- C1, C3 and C5 are cryptographically bound operator commitments (law acceptance
  bound to the law-code hash, mandate hash, revocation acceptance bound to the
  policy hash)

The passport carries the decision id, the evidence root and the policy hash; the
evidence itself stays in an admission manifest that answers later why a model was
admitted at all.

## What 007 demonstrates

- the commitment exists before the deployment
- ordering is carried by the Authority's hash-linked audit sequence, not by
  operator timestamps
- the commitment is bound to model generation, to policy version and to mandate
- the commitment is single-use
- a retrospective commitment fails
- complete later evidence does not substitute for the missing commitment

Not claimed: that training was inspected or changed, that weights were attested,
that the operator trained honestly, or that a real deployment binary was securely
bound.

## Tampering tests

AnteGate rejects: modified commitment; commitment for another model generation;
mandate expansion after commitment; retrospective commitment; reused commitment;
wrong policy version; complete evidence without prior commitment; modified
identity evidence; wrong law hash; forged Authority probe; evidence belonging to
another model; modified passport; tampered revocation state; replay of an older
genuinely signed revocation state.

## Runtime properties

After admission there is one signed passport, two independently operated
gateways, no shared application state and no shared private keys. A gateway holds
only the Authority public key: it can neither issue a passport nor write global
revocation. Central revocation takes effect at both services without changing
either of them. The trust service is not trusted; every response it serves is
verified locally against the Authority key.

Availability is a stated trade-off, not a novelty claim:

```text
fresh valid trust state          -> operation allowed if the credential is valid
Authority/Trust unavailable
  + cached state inside TTL      -> continue
cached state beyond TTL          -> fail closed
```

## The police layer (005)

Part of the artifact, not a headline claim. A local rule scores an action against
the mandate in the passport and the agent's recent refused actions, returning
ALLOW, INVESTIGATE or REVOKE_RECOMMENDED. It can never perform global revocation;
the Authority decides. The claim is only that **behavioral assessment and sanction
authority can be separated in the prototype**, which is not itself a new idea.

## Relationship to prior work

Prior work already covers substantial parts of: frontier-model licensing and
approval regulation; cryptographic precommitment; multiparty approval; AI-agent
identity; workload identity; authorization; revocation; runtime enforcement;
auditability; and external infrastructure for AI agents.

> **AnteGate does not claim novelty for these components individually. Its
> contribution is a reproducible executable composition around one falsifiable
> property: a required pre-deployment condition remains enforceable later and
> cannot be manufactured retrospectively by an already deployed model.**

## Limitations

See `SECURITY_LIMITATIONS.md`. The three that matter most: ordering rests on a
single Authority's audit sequence; trust-state freshness depends on the gateway's
local clock; compromise of the Authority signing key compromises the domain.

## Author

Alexis Basilakis — independent research prototype, Austria. No institutional
affiliation is claimed and no institution endorses this work.

## License

MIT, see `LICENSE`.
