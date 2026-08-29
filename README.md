# CROA Minimal Reference Harness (MRH)

**A vendor-neutral, runnable demonstrator of CROA's enforcement behaviour — using no commercial software.**

> **This is a demonstrator, not a production implementation.** It exists so anyone can *see the architecture behave* and *inspect the audit log it produces* in a few minutes, on a clean machine, with only the Python standard library. It uses demo HMAC keys in place of real cryptography and key management, and mock C1–C7 components. Do not deploy it.

> **And it is not evidence.** The harness is a self-contained mock: the code that enforces a rule and the assertion that checks the rule are the same program. So a passing run shows that *this mock behaves as the specification describes* — it does **not** show that a real implementation has the properties, and it is not an experiment. Read it as an illustration of the mechanism and of the shape of the evidence record. What CROA's evidence base actually contains, and what it does not, is set out in [`docs/limitations.md`](https://github.com/CROA-Project/CROA/blob/main/docs/limitations.md) in the specification repository.
>
> Making that circularity go away is a genuinely useful contribution, and the most valuable one this repository can receive: see [What is *not* tested here](#what-is-not-tested-here).

Companion to the **CROA — Constrained Reachability Orchestration Architecture** Public Review Draft ([DOI 10.5281/zenodo.21063423](https://doi.org/10.5281/zenodo.21063423)). Published by **The CROA Project**. License: **Apache-2.0**.

---

## Run it (≤ 2 minutes)

Requires Python ≥ 3.8. No dependencies.

```bash
make demo      # or:  python3 -m mrh
make test      # run the scenario tests
```

You will see six reference scenarios pass, a sample `C5` event log written to `c5_log.jsonl`, and the audit chain verified.

## What it demonstrates

The harness runs a governed action through the gauntlet **C3 → C2 → C7 → C6**, recording every decision in **C5**:

| Component | Role in the harness |
|---|---|
| **C1** Policy Authority | Holds the registered invariants; issues signed, time-bounded **Governed Exception** authorizations (the agent cannot). |
| **C3** Path Resolver | Grounds the target against a small "golden record"; unregistered targets fail before evaluation. |
| **C2** Execution Governor | Evaluates invariants → `PERMIT` / `PERMIT_WITH_AUTHORIZATION` / `DENY`. |
| **C7** Contract Compiler | Compiles a **single-use, content-addressed, time-bounded, signed** Compiled Commitment (CC). |
| **C6** Execution Firewall | Admits **only** a valid, unexpired, unredeemed CC; everything else is blocked. |
| **C5** Audit Store | Append-only, hash-chained, signed event log; a `verify()` recomputes the chain. |

## The reference scenarios

| Scenario | Demonstrates |
|---|---|
| **Positive path** | A permitted read produces `PERMIT → CC_COMPILED → EXECUTION_AUTHORIZED`. |
| **NT-001** non-CC execution blocked | An operation with no Compiled Commitment is blocked (`CC_NOT_FOUND`). |
| **NT-002** expired CC blocked | A commitment past its validity is blocked (`CC_EXPIRED`). |
| **NT-003** replay blocked | A redeemed commitment cannot be reused (`CC_ALREADY_REDEEMED`). |
| **NT-004** unregistered context blocked | An action against a target absent from the golden record is stopped at C3 (`CONTEXT_FAILURE`); C2 is never reached. |
| **Governed exception** | An invariant-violating action is `DENY`-ed on its own, then permitted only via a C1-signed authorization as `PERMIT_WITH_AUTHORIZATION`. The **authorization is single-use**: the compiled commitment carries the authorization's reference, C5 records its `auth_id`, and C1 marks it spent once it backs an admitted execution — so replaying the *authorization* within its TTL is `DENY`-ed, not just replaying the CC. |

The governed-exception scenario demonstrates the one deliberate exception path (Constrained Execution) — the architecture's most sensitive surface, hence exercised explicitly (including that a signed authorization admits exactly **one** execution). It covers **part** of the specification's reference negative test **NT-007** (Appendix Q). NT-007 has four steps; this scenario implements the **replay** step only. Its **scope-widening** step (an authorization presented against an action outside its compiled `cc.exception_scope`) and its **concurrent double-redemption** step (two simultaneous presentations of the same authorization to two `C6` instances) are **not implemented here**. The scope-widening case would be a ten-line addition and is an excellent first contribution.

**On the reference negative tests.** The published specification (Appendix Q) defines **NT-001 … NT-007**; the next version adds **NT-008** (authority non-expansion). This minimal harness implements **NT-001 – NT-004** — the mechanically checkable execution-boundary tests (non-CC, expired CC, replay, unregistered context) — plus the replay step of NT-007. The rest are intentionally out of scope here: **NT-005** (ambiguous E3 invariant → fail-closed deny) needs an E3 semantic analyzer, **NT-006** (trajectory / cumulative constraint) needs C4 trajectory state, and **NT-008** needs a delegation model — each beyond what a dependency-free demonstrator should mock. All three are prime candidates for a contributed extension.

## The audit log

`c5_log.jsonl` contains one JSON event per line, each with `event.type`, `event.subject_id`, `event.emitter_id`, `event.chain_hash`, `event.emitter_signature`, and a decision basis. The point: **every decision — permit and deny — is reconstructable from the log alone**, and the hash chain is what would make alteration of a recorded event detectable (`AuditStore.verify()` recomputes it).

Two honest caveats. First, the scenarios verify that the chain is *intact*; **no scenario tampers with an event and asserts that verification then fails**, so `verify()`'s failure branches are not exercised. Second, a chain establishes the ordering and non-alteration of the events it contains — not that every governed action produced one. In the specification, capture completeness follows from the fail-closed gate, not from the chain; see property **P-E** in [`spec/properties.md`](https://github.com/CROA-Project/CROA/blob/main/spec/properties.md).

## Layout

```
mrh/
├── audit.py       # C5: append-only, hash-chained, signed events + chain verification
├── components.py  # mock C1, C2, C3, C6, C7
├── harness.py     # wires the gauntlet together
├── scenarios.py   # positive path + NT-001..004 + governed exception
└── __main__.py    # CLI: run all, write c5_log.jsonl, verify chain
tests/test_mrh.py  # scenario + chain tests (stdlib unittest)
```

## What is *not* tested here

Stated plainly, because the gaps are more useful to a contributor than the passing scenarios are.

**The scenarios are cooperative.** Every one of them calls the API in the intended order with well-formed inputs. Nothing yet tries to *break* the harness. In particular, no scenario:

- hand-builds a Compiled Commitment without going through `C7` and presents it at `C6`;
- flips a byte of a CC signature — so `ExecutionFirewall`'s `CC_SIGNATURE_INVALID` path is never reached;
- mutates the action after compilation but before presentation;
- presents a CC issued for one subject under another subject's identity;
- tampers with an event in the log and asserts that `AuditStore.verify()` reports a chain break — so **both** of `verify()`'s failure branches are dead code as far as the test suite is concerned;
- presents an authorization against an action outside its compiled `cc.exception_scope` (the missing half of NT-007);
- drives the same CC, or the same authorization, from several threads at once.

That last one is worth singling out. `ExecutionFirewall.redeem` is a check-then-act on a plain `set`, with no lock — so the single-use guarantee it demonstrates is, in this mock, racy by construction. The specification requires redemption to be a single linearizable compare-and-swap against one shared authority (Part II §4.8). **A concurrency scenario here would be expected to fail**, and that failure would be informative rather than embarrassing: it is the difference between what the specification requires and what a naive implementation does.

**Good first contributions**, roughly in order of value:

1. An adversarial scenario module that tries each of the bullets above and asserts the block. This turns cooperative demonstrations into genuine property tests.
2. A concurrency scenario for CC and authorization redemption (see above).
3. The scope-widening step of NT-007 — about ten lines.
4. NT-005 or NT-006, which need a stub E3 analyzer or a minimal C4 counter respectively.

## Contributing

Found a way to make the harness admit something it shouldn't, or a scenario worth adding? That is exactly the kind of finding the CROA public review wants — open an issue or a discussion in the main [`CROA`](https://github.com/CROA-Project/CROA) repository. A scenario that *fails* is as welcome as one that passes; see the list above for where we already expect the mock to fall short.
