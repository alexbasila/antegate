# AnteGate architecture

Four independent processes, four ports, four separate state directories, no
shared file system and no shared audit.

## Participants

**Authority.** Sole holder of the domain signing key. Issues pre-deployment
commitments, executes the AP-1 boundary probe, adjudicates admission criterion by
criterion, issues passports, writes revocation and publishes the signed
revocation bundle. Keeps its own hash-linked audit chain, whose sequence is the
authoritative clock for ordering.

**Identity issuer.** A separate demonstration instance with its own key, issuing
signed operator-identity evidence bound to a model id. Outside the Authority.

**Trust service.** A relay that serves policy, public key and the signed
revocation bundle over HTTP. It holds no key and is deliberately not trusted:
every response is verified by the consumer against the Authority public key.

**Company gateways.** Two independently operated protected services. Each holds
only the Authority public key (handed over out of band), its own configuration, a
cached signed trust state and its own audit chain. A gateway can neither issue a
passport nor write global revocation.

## The chain

```text
domain policy
   -> pre-deployment commitment   (signed, generation/policy/mandate bound, single use)
   -> deployment registration     (operator-signed manifest, artifact hash)
   -> evidence package            (C1 law, C2 identity, C3 mandate, C4 probe, C5 revocation)
   -> admission decision          (criterion verdicts, evidence root, signed, archived)
   -> passport                    (carries decision id, evidence root, commitment id)
   -> runtime access at both gateways
   -> domain-wide revocation
```

## Trust-state handling at a gateway

1. Refresh the bundle from the trust service when reachable.
2. Verify its signature against the Authority public key; an invalid response
   closes the gate and never overwrites the cache.
3. Reject a validly signed bundle whose version is lower than the highest already
   seen (rollback).
4. Serve requests from the cached state while it is inside the TTL set by the
   bundle; fail closed once it is beyond the TTL.

## Report artifacts

Every run writes a dated report containing the ports, the state directories, the
policy and law hashes, the criterion table, each tampering test, the network trust
smoke tests, all audit chain heads and the falsification list with its verdict.
