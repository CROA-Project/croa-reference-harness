# CROA Minimal Reference Harness (MRH)

**A vendor-neutral, runnable demonstrator of CROA's enforcement behaviour — using no commercial software.**

> **This is a demonstrator, not a production implementation.** It exists so anyone can *see the
> architecture behave* and *inspect the audit log it produces* in a few minutes, on a clean machine,
> with only the Python standard library. It uses demo HMAC keys in place of real cryptography and key
> management, and mock components. Do not deploy it.
>
> **And it is not evidence.** The harness is a self-contained mock: the code that enforces a rule and
> the assertion that checks the rule are the same program. A passing run shows that *this mock behaves
> as the specification describes* — not that a real implementation has the properties. What CROA's
> evidence base actually contains is set out in
> [`docs/limitations.md`](https://github.com/CROA-Project/CROA/blob/main/docs/limitations.md).

Companion to the **CROA — Constrained Reachability Orchestration Architecture** Public Review Draft
([DOI 10.5281/zenodo.21063423](https://doi.org/10.5281/zenodo.21063423)). Published by **The CROA
Project**. License: **Apache-2.0**.

---

## September 2026 — three defects found, four fixed

An independent enterprise-architecture audit reviewed this harness line by line and **reproduced two
bypasses**. The CROA Project reproduced them, found a third, and fixed four. The full register, with
what each defect was and what remains open, is
[`spec/known-defects-harness.md`](https://github.com/CROA-Project/CROA/blob/main/spec/known-defects-harness.md).

| | Defect | State |
|---|---|---|
| **H-01** | One single-use exception authorization admitted **two** executions | **fixed** |
| **H-02** | A commitment compiled for one subject was admitted under another; the presented operation was never compared to the commitment | **fixed** |
| **H-03** | `cc.id` mixed a random UUID into the digest, so it was not a content address | **fixed** |
| **H-04** | `verify()` recomputed the chain and did no causal correlation, so the H-01 log verified as valid | **fixed** |
| **H-05** | No `C4` (trajectory state), no admission layer | **open** |
| **H-06** | No network boundary, so property P4 is not demonstrated | **open** |
| **H-07** | The scenario suite was entirely cooperative | **partly closed** — an adversarial group now exists; more is welcome |

**One correction the README owed you.** This file previously said a signed authorization admits
"exactly one" execution. That was **false** when written: two decisions taken before the first
redemption produced two commitments, and both were admitted. It is true now, and there is a test that
fails if it stops being true.

**H-01 was not a flaw in the architecture.** Part II §4.8 of the specification already requires
redemption to be a single atomic linearizable compare-and-swap. This harness performed a
check-then-act instead. The demonstrator did not implement what the document it demonstrates requires.

### Breaking API change

`C6` now needs to know **who** is presenting and **what** they are asking to do:

```diff
- firewall.redeem(cc, now)
+ firewall.redeem(cc, now, subject_id, operation)

- harness.present(cc, now, sid)
+ harness.present(cc, now, subject_id, operation)
```

Both arguments are mandatory. The unsafe call is no longer expressible — which is the point: a
boundary that can be called without an identity will eventually be called without one.

---

## Run it (≤ 2 minutes)

Requires Python ≥ 3.8. No dependencies.

```
make demo      # or:  python3 -m mrh
make test      # run the scenario and adversarial tests
```

You will see twelve scenarios pass, a sample `C5` event log written to `c5_log.jsonl`, and the audit
chain verified — chain *and* decision correlation.

## What it demonstrates

The harness runs a governed action through the gauntlet **C3 → C2 → C7 → C6**, recording every
decision in **C5**:

| Component | Role in the harness |
|---|---|
| **C1** Policy Authority | Holds the registered invariants; issues signed, time-bounded **Governed Exception** authorizations (the agent cannot). Reserving one is an atomic test-and-set. |
| **C3** Path Resolver | Grounds the target against a small "golden record"; unregistered targets fail before evaluation. |
| **C2** Execution Governor | Evaluates invariants → `PERMIT` / `PERMIT_WITH_AUTHORIZATION` / `DENY`. A decision is not a reservation. |
| **C7** Contract Compiler | Reserves the authorization, then compiles a **single-use, content-addressed, time-bounded, signed** Compiled Commitment. A spent authorization yields no commitment. |
| **C6** Execution Firewall | Admits **only** a valid, unexpired, unredeemed commitment, presented by the subject it was compiled for, for the operation it authorizes. |
| **C5** Audit Store | Append-only, hash-chained, signed event log. `verify()` checks the chain **and** correlates decisions. |

## The scenarios

**Cooperative** — the mechanism working when called correctly:

| Scenario | Demonstrates |
|---|---|
| Positive path | A permitted read produces `PERMIT → CC_COMPILED → EXECUTION_AUTHORIZED`. |
| **NT-001** | An operation with no commitment is blocked (`CC_NOT_FOUND`). |
| **NT-002** | A commitment past its validity is blocked (`CC_EXPIRED`). |
| **NT-003** | A redeemed commitment cannot be reused (`CC_ALREADY_REDEEMED`), and the resulting log still verifies. |
| **NT-004** | An action against an unregistered target is stopped at C3; C2 is never reached. |
| Governed exception | An invariant-violating action is denied, then permitted once via a C1-signed authorization, which is then spent. |

**Adversarial** — the mechanism refusing when called incorrectly. These are the ones that matter:

| Scenario | Demonstrates |
|---|---|
| **H-01** | Two decisions on one authorization before any redemption still yield one commitment and one execution. The second compilation fails. |
| **H-02** | A commitment compiled for `subject-A` presented as `subject-B` is refused (`CC_SUBJECT_MISMATCH`) and nothing is written to C5 under B. |
| **H-02b** | An operation mutated after compilation is refused (`CC_OPERATION_MISMATCH`). |
| **H-03** | The same inputs give the same `cc.id`; a commitment whose identifier is forged **and re-signed** is refused (`CC_ID_NOT_CONTENT_ADDRESSED`). |
| **H-04** | A log with two executions from one authorization fails verification, even though its chain is intact. |
| **H-04b** | An execution citing a commitment that was never compiled fails verification. |

The test suite adds forged signatures, deleted events, tampered events, and **two 100-thread races** —
one on authorization reservation, one on commitment redemption — each of which must admit exactly one
winner.

## The audit log

`c5_log.jsonl` contains one JSON event per line, each with `event.type`, `event.subject_id`,
`event.emitter_id`, `event.chain_hash`, `event.emitter_signature`, and a decision basis.

`AuditStore` now exposes two checks, deliberately separate:

- **`verify_chain()`** — recomputes the hash chain and each signature. This establishes that the
  events present were not altered or reordered. **It establishes nothing else**, and before September
  2026 it was all `verify()` did.
- **`verify_decisions()`** — the Appendix G.2.4 correlation: every commitment cites an earlier permit,
  at most one commitment per permit, at most one execution per commitment, **at most one execution per
  authorization**, and the executing subject is the one the commitment was compiled for.
- **`verify()`** — both.

A chain establishes the ordering and non-alteration of the events it contains — not that every
governed action produced one. Capture completeness follows from the fail-closed gate, not from the
chain; see property **P-E** in
[`spec/properties.md`](https://github.com/CROA-Project/CROA/blob/main/spec/properties.md).

## Layout

```
mrh/
├── audit.py       # C5: chained signed events + chain and decision verification
├── components.py  # mock C1, C2, C3, C6, C7
├── harness.py     # wires the gauntlet together
├── scenarios.py   # cooperative + adversarial scenarios
└── __main__.py    # CLI: run all, write c5_log.jsonl, verify
tests/test_mrh.py  # scenario, adversarial and concurrency tests (stdlib unittest)
```

## What is still *not* tested here

Stated plainly, because the gaps are more useful to a contributor than the passing scenarios are.

- **No `C4`, no trajectory state** — so **NT-006** is not implemented, and no cumulative constraint is
  ever evaluated (H-05).
- **No admission layer** — no authentication, no RBAC, no Agent Qualification Level. `subject_id` is
  taken as authentic because the harness has nothing that could authenticate it (H-05).
- **No `E3` semantic analyzer** — so **NT-005** (ambiguous verdict → fail-closed deny) is absent.
- **No delegation model** — so **NT-008** (authority non-expansion) is absent. H-02 covers only the
  base case of subject substitution, not delegation.
- **No network boundary and no governed system.** `C6` returns a verdict; it does not perform an
  operation, and there is no second path that must be shown to be unreachable. NT-001 shows that a
  call with no commitment is refused — **not** that a non-CC execution is structurally impossible.
  This is the most load-bearing condition of CROA's central claim, and the harness does not test it
  at all (H-06).
- **No cross-process or cross-instance state.** The atomic reservation is a `threading.Lock` in one
  process. A real deployment needs one shared authority — a conditional write, a compare-and-swap, or
  a transaction — visible to every `C6` and `C7`. The concurrency tests here prove the *shape* of the
  guarantee, not that it survives distribution.
- **No schema validation.** Commitments and events still do not validate against the specification's
  JSON schemas (H-03's remaining half). This is the next thing worth fixing.

**Good first contributions**, roughly in order of value:

1. Make the harness's commitments and events validate against `spec/schemas/`, and fail CI on drift.
2. A real network boundary and a target system, so P4 can be tested on external effects (H-06).
3. A minimal `C4` and NT-006.
4. A delegation model and NT-008.
5. Multi-process concurrency against a shared redemption store.

## Contributing

Found a way to make the harness admit something it shouldn't? That is exactly the kind of finding the
CROA public review wants — open an issue or a discussion in the main
[`CROA`](https://github.com/CROA-Project/CROA) repository. A scenario that *fails* is as welcome as
one that passes, and the last person to find one had three of them.
