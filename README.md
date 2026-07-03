# CROA Minimal Reference Harness (MRH)

**A vendor-neutral, runnable demonstrator of CROA's enforcement behaviour — using no commercial software.**

> **This is a demonstrator, not a production implementation.** It exists so anyone can *see the architecture behave* and *inspect the audit log it produces* in a few minutes, on a clean machine, with only the Python standard library. It uses demo HMAC keys in place of real cryptography and key management, and mock C1–C7 components. Do not deploy it.

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

| Scenario | Proves |
|---|---|
| **Positive path** | A permitted read produces `PERMIT → CC_COMPILED → EXECUTION_AUTHORIZED`. |
| **NT-001** non-CC execution blocked | An operation with no Compiled Commitment is blocked (`CC_NOT_FOUND`). |
| **NT-002** expired CC blocked | A commitment past its validity is blocked (`CC_EXPIRED`). |
| **NT-003** replay blocked | A redeemed commitment cannot be reused (`CC_ALREADY_REDEEMED`). |
| **NT-004** unregistered context blocked | An action against a target absent from the golden record is stopped at C3 (`CONTEXT_FAILURE`); C2 is never reached. |
| **Governed exception** | An invariant-violating action is `DENY`-ed on its own, then permitted only via a C1-signed authorization as `PERMIT_WITH_AUTHORIZATION`. The **authorization is single-use**: the compiled commitment carries the authorization's reference, C5 records its `auth_id`, and C1 marks it spent once it backs an admitted execution — so replaying the *authorization* within its TTL is `DENY`-ed, not just replaying the CC. |

The governed-exception scenario demonstrates the one deliberate exception path (Constrained Execution) — the architecture's most sensitive surface, hence tested explicitly (including that a signed authorization admits exactly **one** execution). It corresponds to the specification's reference negative test **NT-007** (Appendix Q): authorization replay and scope-widening are both blocked.

**On the reference negative tests.** The specification's Appendix Q defines **NT-001 … NT-006**. This minimal harness implements **NT-001 – NT-004** — the mechanically checkable execution-boundary tests (non-CC, expired CC, replay, unregistered context). **NT-005** (ambiguous E3 invariant → fail-closed deny) and **NT-006** (trajectory / cumulative constraint) are intentionally out of scope here: they require an E3 semantic analyzer and C4 trajectory state respectively, beyond what a dependency-free demonstrator should mock. They are prime candidates for a contributed extension.

## The audit log

`c5_log.jsonl` contains one JSON event per line, each with `event.type`, `event.subject_id`, `event.emitter_id`, `event.chain_hash`, `event.emitter_signature`, and a decision basis. The point: **every decision — permit and deny — is reconstructable from the log alone**, and the hash chain makes tampering detectable (`AuditStore.verify()`).

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

## Contributing

Found a way to make the harness admit something it shouldn't, or a scenario worth adding? That is exactly the kind of finding the CROA public review wants — open an issue or a discussion in the main `croa` repository.
