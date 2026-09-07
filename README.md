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
| **H-03** | `ecc.id` mixed a random UUID into the digest, so it was not a content address | **fixed** |
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
| **C1** Policy Authority | Holds the registered invariants; issues signed, time-bounded **Governed Exception** authorizations, each carrying a bounded `exception_scope` (the agent cannot issue these). |
| **C3** Path Resolver | Grounds the target against a small Federated Context Registry. An unregistered target — or an unavailable resolver — fails closed before evaluation. |
| **C2** Execution Governor | Evaluates invariants → `PERMIT` / `PERMIT_WITH_AUTHORIZATION` / `DENY`, and returns the invariant state that goes on the record. A decision is not a reservation. |
| **C7** Contract Compiler | Compiles a **single-use, content-addressed, time-bounded, signed** Execution Change Contract, binding `ecc.auth_ref` and `ecc.exception_scope` on the exception path. It spends nothing. |
| **C6** Execution Firewall | Admits **only** a valid, unexpired, unredeemed ECC, presented by the subject it was compiled for, for an operation inside the scope it authorizes. Holds **no** redemption state. |
| **Redemption registry** | The one authoritative, linearizable compare-and-swap shared by every C6 (§4.8). Claims `ecc.id` and `ecc.auth_ref` in a single all-or-nothing operation. |
| **C5** Audit Store | Append-only, hash-chained, signed event log over an Appendix R write-ahead log. `verify()` checks the chain **and** correlates decisions. |

## The scenarios

**Cooperative** — the mechanism working when called correctly:

| Scenario | Demonstrates |
|---|---|
| Positive path | A permitted read produces `PERMIT → ECC_COMPILED → EXECUTION_AUTHORIZED → EXECUTION_COMPLETED → EFFECT_ATTESTED`. |
| **NT-001** | An operation with no ECC is blocked (`ECC_NOT_FOUND`). |
| **NT-002** | An ECC past its validity is blocked (`ECC_EXPIRED`) — and refusing it does **not** consume its single use. |
| **NT-003** | A redeemed ECC cannot be reused (`ECC_ALREADY_REDEEMED`), and the resulting log still verifies. |
| **NT-004** | An action against an unregistered target is stopped at C3; C2 is never reached. An unavailable C3 fails closed too. |
| **NT-005** | An `E3` analyzer that returns `AMBIGUOUS` produces a `DENY` whose `event.decision_basis` is `AMBIGUOUS` and which records the pinned `event.analyzer_version`. Fail-deny is a recorded decision, not a silent one. |
| **NT-006** | Five permitted exports of 90 subjects reach the 450 alert threshold; C4 raises a `TRAJECTORY_ALERT` after the fifth; the sixth would reach 510 against a hard limit of 500 and is denied, its `trajectory_state_id` linking back to the alert. The cumulative total is recomputed from C5 alone. |
| **NT-007** | All four steps: first use admitted, a second ECC on the same authorization refused, an out-of-scope target refused, and two concurrent presentations to two C6 instances admitting exactly one. |
| **NT-008** | I8 in both clauses. (a) A delegation within `O`'s scope is admitted — the control case, without which the test is vacuous — while tokens widening the action class, target, parameter constraints, validity window or depth each fail deny on their own. (b) Four laundering arrangements, in which `S` submits an action only `O` holds, are all refused at the Agent Surface, including `S` presenting `O`'s own ECC at the boundary. |
| Evidence Pack | Appendix Q Part 1, assembled from the C5 record of a real run rather than from a template: worked examples per event type, the three negative-test reports in the Q.1.8 shape, and a verification block that states what the pack does **not** establish. |

**Adversarial** — the mechanism refusing when called incorrectly. These are the ones that matter:

| Scenario | Demonstrates |
|---|---|
| **H-01** | Two ECCs compiled against one authorization still yield one admitted execution. The second is refused at the boundary. |
| **H-02** | An ECC compiled for `subject-A` presented as `subject-B` is refused, and nothing is written to C5 under B. |
| **H-02b** | An operation mutated after compilation falls outside `ecc.authorization_scope` and is refused. |
| **H-03** | The same inputs give the same `ecc.id`; an ECC whose identifier is forged **and re-signed** is refused. |
| **H-04** | A log with two executions from one authorization fails verification, even though its chain is intact. |
| **H-04b** | An execution citing an ECC that was never compiled fails verification. |
| Shared registry | One ECC presented to two C6 instances sharing one registry is admitted once. **The negative control is a test too:** give each instance its own registry — the pre-v1.0.1 shape — and the same ECC is admitted twice and the governed system takes two effects. |
| Exception scope | A permit broader than the waiver: an operation inside `ecc.authorization_scope` but outside `ecc.exception_scope` is refused, and the authorization stays unspent. |

The test suite adds forged signatures, deleted events, tampered events, a stale invariant registry,
**two 100-thread races** — one on ECC redemption, one on a shared authorization — and a **forked
eight-process race** on the file-lock registry, each of which must admit exactly one winner.

## What changed in v1.0.1

Two things, both structural rather than cosmetic.

**Redemption moved to where §4.8 puts it.** The September 2026 fix for H-01 made C7 spend the
authorization at compile time, behind a lock inside C1. That closed the reproduced bypass, but it
left a second hole the audit did not reach: each `ExecutionFirewall` carried its own `redeemed` set,
so two firewall instances each admitted the same contract once. §4.8 calls a per-instance redemption
record non-conformant wherever more than one instance can admit operations for the same system. The
firewall now holds no redemption state at all — it holds a reference to a shared registry, and
`ecc.id` and `ecc.auth_ref` are claimed in **one** all-or-nothing compare-and-swap. C7 spends
nothing: §4.8 anticipates a second ECC being compiled against a spent authorization and requires C6
to refuse it at admission, which is both the specified place and the only place that holds when there
is more than one compiler.

Three registry backends are provided, and the choice is a deployment decision, not a detail:

| Backend | Shared across | Use |
|---|---|---|
| `InProcessRegistry` | threads | One process admits for one system. The default here. |
| `FileLockRegistry` | processes on one host | The smallest honest demonstration of the CAS contract; the eight-process race test uses it. |
| `ConditionalWriteRegistry` | hosts | The production shape. Maps onto etcd `Txn`, DynamoDB `ConditionExpression`, Postgres `ON CONFLICT DO NOTHING`, Redis `SET NX`. |

**The C5 path implements Appendix R.** Events are chained, signed by a separately-trusted local
signer, and written to an append-only write-ahead log with a real `fsync` before the next action is
admitted. Replication to the central store is off the admission path, an unreplicated event is a
full-status evidence record, and `reconcile()` enforces R.4 invariant 7 — the same verification must
hold locally and centrally. Replication lag is a declared, monitored parameter that alerts when
breached.

The two are deliberately separate. §4.8: "the linearizable redemption authority is distinct from, and
MUST commit ahead of, asynchronous evidence materialization." Conflating them is the specific error
the section warns against, so the registry lives in `mrh/redemption.py` and the evidence path in
`mrh/wal.py`, and neither imports the other.

## What v1.0.1 adds beyond the boundary

Lot 2 made the execution boundary conformant. The tests that need more than a boundary
need three components the harness did not have.

**An `E3` analyzer that is allowed to not know.** Rice's theorem denies an exact, total,
deterministic procedure for a semantic property of arbitrary content, so `mrh/invariants.py`
gives the analyzer three outcomes rather than two and a declared budget beyond which it
must return `AMBIGUOUS`. Part I §2.6 then makes that a deny. The pinned version travels
onto every decision it took part in as `event.analyzer_version` — without it, two decisions
on identical inputs that differ because the analyzer changed are indistinguishable from a
determinism failure.

**C4, which watches sequences.** `mrh/trajectory.py` implements the four trajectory rule
profiles of §4.6.3, and the cumulative ones (`TP-C`, `TP-X`) are where the interesting
failure lives: an aggregate crossing a threshold is not visible to any single-action check.
Two details are normative rather than convenient. The agent's self-reported state is not an
input, so only an action that actually completed accumulates — otherwise an agent drives
the counter to its limit with requests that were all refused. And C4 being unavailable is
fail-deny, with `event.deny_reason` naming C4 as the cause.

**Governed delegation, and the two ways I8 fails.** `mrh/delegation.py` implements the D3
canonical scope profile and its five-dimension subset test. Clause (a) — attenuation — is
that test. Clause (b) — no laundering — is not in this module at all: it is the Agent
Surface refusing an action class the *submitting* subject does not hold, before any
component that could be persuaded has seen the request. That is why NT-008 Part B applies
to every deployment, delegating or not.

The subtlety that is easy to invert: parameter constraints compose by logical implication,
not by set inclusion. The narrower predicate is the subset. Getting it backwards admits
every widening token, so the direction is asserted dimension by dimension in the tests.

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
  call with no contract is refused — **not** that a non-ECC execution is structurally impossible.
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
