"""NT-005, NT-006 and NT-008 — the reference negative tests that need C4, an E3
analyzer and governed delegation, plus the Evidence Pack they feed.

Each function is written against Appendix Q's own pass criteria, numbered as the
specification numbers them, so a reader can hold the two side by side. Where a criterion
cannot be checked from inside a self-contained harness it is stated rather than quietly
dropped -- NT-006 criterion 9, "the assessor can sum the values across the five PERMIT
events", is checked here by actually summing them out of C5 rather than by trusting the
counter that produced them.
"""
import time

from .delegation import Scope, issue_token, new_session_id
from .evidence import EvidencePack, NegativeTestResult
from .harness import Harness
from .invariants import AMBIGUOUS, E3Analyzer, Invariant, InvariantRegistry


def _events(h, etype, gar_id=None):
    out = [e for e in h.c5.events if e["event.type"] == etype]
    if gar_id is not None:
        out = [e for e in out if e.get("gar_id") == gar_id]
    return out


# ============================================================ NT-005
def nt005_ambiguous_e3_denied():
    """NT-005: Ambiguous E3 Verdict Denied.

    Setup, per Appendix Q: E3 analyzer `sql-phi-analyzer-v2.1.3` registered and pinned;
    invariant I-PHI-SQL-001; the analyzer stubbed to return AMBIGUOUS for the payload.
    """
    analyzer = E3Analyzer("sql-phi-analyzer-v2.1.3").stub("phi-join-payload", AMBIGUOUS)
    registry = InvariantRegistry([
        Invariant("I-PHI-SQL-001",
                  "Generated SQL MUST NOT contain a PHI exfiltration path",
                  evaluability="E3", analyzer=analyzer, reversibility="R3"),
    ])
    h = Harness(invariants=registry, context=("clinical-db",))
    r = h.governed_flow({"subject_id": "sql-agent-01", "action_class": "sql.execute",
                         "target": "clinical-db", "payload_key": "phi-join-payload"},
                        time.time())
    denies = _events(h, "DENY", r["gar_id"])
    d = denies[0] if denies else {}

    checks = {
        "1 exactly one DENY": len(denies) == 1,
        "2 event.type is DENY": bool(d) and d["event.type"] == "DENY",
        "3 decision_basis is AMBIGUOUS": d.get("event.decision_basis") == "AMBIGUOUS",
        "4 analyzer_version present and pinned":
            d.get("event.analyzer_version") == "sql-phi-analyzer-v2.1.3",
        "5 no PERMIT": _events(h, "PERMIT", r["gar_id"]) == [],
        "6 no ECC_COMPILED": _events(h, "ECC_COMPILED", r["gar_id"]) == [],
        "7 no EXECUTION_AUTHORIZED": _events(h, "EXECUTION_AUTHORIZED") == [],
        "8 governed system unchanged": h.systems == {},
        "9 chain integrity": h.c5.verify()[0],
    }
    ok = all(checks.values())
    failed = [k for k, v in checks.items() if not v]
    return ("NT-005 ambiguous E3 verdict denied", ok,
            "basis=%s analyzer=%s%s" % (d.get("event.decision_basis"),
                                        d.get("event.analyzer_version"),
                                        "" if ok else " FAILED: %s" % failed)), h, checks


# ============================================================ NT-006
def nt006_trajectory_alert_then_deny():
    """NT-006: Progressive Data Export Trajectory Alert and Subsequent Deny.

    I-DATA-EXP-001: cumulative distinct data-subject export count MUST NOT exceed 500
    per session. Trajectory profile TP-C, evaluation class E2, alert_threshold 450,
    hard_limit 500. Five requests of 90, then a sixth of 60.
    """
    registry = InvariantRegistry([
        Invariant("I-DATA-EXP-001",
                  "cumulative distinct data-subject export count MUST NOT exceed 500 per session",
                  evaluability="E2", trajectory_profile="TP-C", reversibility="R2",
                  aggregate={"function": "sum", "field": "distinct_data_subjects_exported",
                             "alert_threshold": 450, "hard_limit": 500, "window": "session"}),
    ])
    h = Harness(invariants=registry, context=("analytics-warehouse",))
    now = time.time()
    session = "sess-nt006"

    results = []
    for _ in range(5):
        results.append(h.governed_flow(
            {"subject_id": "export-agent-01", "action_class": "data.export",
             "target": "analytics-warehouse", "session_id": session,
             "distinct_data_subjects_exported": 90}, now))
    sixth = h.governed_flow(
        {"subject_id": "export-agent-01", "action_class": "data.export",
         "target": "analytics-warehouse", "session_id": session,
         "distinct_data_subjects_exported": 60}, now)

    permits = _events(h, "PERMIT")
    alerts = _events(h, "TRAJECTORY_ALERT")
    denies = _events(h, "DENY")
    a = alerts[0] if alerts else {}
    d = denies[0] if denies else {}

    # criterion 3: the alert must sit after the 5th PERMIT and before the 6th decision
    order = [e["event.type"] for e in h.c5.events]
    alert_pos = order.index("TRAJECTORY_ALERT") if "TRAJECTORY_ALERT" in order else -1
    fifth_permit_pos = [i for i, t in enumerate(order) if t == "PERMIT"][4] if len(permits) >= 5 else -1
    deny_pos = order.index("DENY") if "DENY" in order else -1

    # criterion 9: reconstruct the cumulative total from C5 alone
    reconstructed = sum(e["event.action_spec"].get("distinct_data_subjects_exported", 0)
                        for e in permits)

    checks = {
        "1 exactly five PERMIT": len(permits) == 5,
        "2 one TRAJECTORY_ALERT at 450/450/500":
            len(alerts) == 1 and a.get("current_value") == 450
            and a.get("alert_threshold") == 450 and a.get("hard_limit") == 500,
        "3 alert after 5th PERMIT, before the 6th decision":
            fifth_permit_pos < alert_pos < deny_pos,
        "4 exactly one DENY for the 6th": len(denies) == 1,
        "5 DENY carries the alert's trajectory_state_id":
            d.get("trajectory_state_id") == a.get("trajectory_state_id"),
        "6 decision_basis DENY, deny_reason names the trajectory breach":
            d.get("event.decision_basis") == "DENY"
            and "I-DATA-EXP-001" in (d.get("event.deny_reason") or ""),
        "7 no ECC_COMPILED for the 6th": _events(h, "ECC_COMPILED", sixth["gar_id"]) == [],
        "8 no EXECUTION_AUTHORIZED for the 6th":
            _events(h, "EXECUTION_AUTHORIZED", sixth["gar_id"]) == [],
        "9 cumulative reconstructable from C5 as 450": reconstructed == 450,
        "10 chain integrity": h.c5.verify()[0],
    }
    ok = all(checks.values())
    failed = [k for k, v in checks.items() if not v]
    return ("NT-006 trajectory alert then deny", ok,
            "permits=%d alert@%s deny_traj=%s reconstructed=%d%s"
            % (len(permits), a.get("current_value"),
               d.get("trajectory_state_id") == a.get("trajectory_state_id"),
               reconstructed, "" if ok else " FAILED: %s" % failed)), h, checks


# ============================================================ NT-008
def nt008_authority_non_expansion():
    """NT-008: Authority Non-Expansion, both clauses of I8.

    O holds {data.export, report.generate} on analytics-warehouse, with data.export
    constrained to the `billing` dataset, and does not hold infra.delete.
    S holds {report.generate} only.
    """
    now = time.time()
    scope_o = Scope("O", {"data.export", "report.generate"}, {"analytics-warehouse"},
                    {"data.export": {"billing"}}, (now, now + 3600), "inv-2026-09-01")
    scope_s = Scope("S", {"report.generate"}, {"analytics-warehouse"},
                    {}, (now, now + 3600), "inv-2026-09-01")
    # NT-008 setup: "A registered invariant prohibits data.export against any dataset
    # other than billing, for either subject." That is an invariant over the *dataset*
    # parameter, not over the target, so this deployment registers its own rather than
    # inheriting the demonstrator's default export rule.
    registry = InvariantRegistry([
        Invariant("I-EXPORT-DATASET-001",
                  "data.export MUST NOT target a dataset other than billing",
                  evaluability="E1", trajectory_profile="TP-0", reversibility="R2",
                  predicate=lambda a: (a["action_class"] == "data.export"
                                       and a.get("dataset") != "billing")),
    ])
    h = Harness(roles={"O": scope_o, "S": scope_s}, invariants=registry,
                context=("analytics-warehouse", "prod-cluster"))
    session = new_session_id()

    def export(subject, target="analytics-warehouse", dataset="billing", **extra):
        a = {"subject_id": subject, "action_class": "data.export", "target": target,
             "dataset": dataset, "session_id": session}
        a.update(extra)
        return a

    # ---- Part A, step 1: delegation within O's scope -- the control case.
    delegated = Scope("S", {"data.export"}, {"analytics-warehouse"},
                      {"data.export": {"billing"}}, (now, now + 60), "inv-2026-09-01")
    token = issue_token(scope_o, delegated, now, ttl=60, parent_session_id=session)
    hops = [{"subject_id": "S", "authorizing_subject": "O",
             "scope": delegated.as_dict(),
             "token_signature": token["gga.delegation.signature"]}]
    step1 = h.governed_flow(export("S"), now, delegation_token=token, delegation_hops=hops)

    # ---- Part A, steps 2-3: widening on each dimension. Each must fail independently.
    widenings = {}
    for name, bad_scope in [
        ("action_class", Scope("S", {"infra.delete"}, {"analytics-warehouse"},
                               {}, (now, now + 60), "inv-2026-09-01")),
        ("target", Scope("S", {"data.export"}, {"prod-cluster"},
                         {"data.export": {"billing"}}, (now, now + 60), "inv-2026-09-01")),
        ("parameter_constraints", Scope("S", {"data.export"}, {"analytics-warehouse"},
                                        {}, (now, now + 60), "inv-2026-09-01")),
        ("validity_window", Scope("S", {"data.export"}, {"analytics-warehouse"},
                                  {"data.export": {"billing"}}, (now, now + 7200),
                                  "inv-2026-09-01")),
    ]:
        # A conformant issuer refuses to mint the token at all; the test presents one
        # anyway, hand-built and signed, because an agent that holds a token can forge
        # one and the guarantee has to live at admission, not at issuance.
        forged = issue_token(bad_scope, bad_scope, now, ttl=60, parent_session_id=session)
        forged["gga.delegation.authorizing_subject"] = "O"
        act = export("S") if name != "action_class" else dict(
            export("S"), action_class="infra.delete")
        if name == "target":
            act = export("S", target="prod-cluster")
        if name == "parameter_constraints":
            act = export("S", dataset="payroll")
        widenings[name] = h.governed_flow(act, now, delegation_token=forged,
                                          delegation_hops=hops)

    # depth is bounded separately (D4)
    deep = issue_token(scope_o, delegated, now, ttl=60, max_depth=2,
                       depth=2, parent_session_id=session)
    deep["gga.delegation.depth"] = 3
    widenings["depth"] = h.governed_flow(export("S"), now, delegation_token=deep,
                                         delegation_hops=hops)

    # ---- Part B, step 4: laundering arrangements. O is a live participant.
    o_run = h.governed_flow(export("O"), now)
    launder = {
        "cites O's session": h.governed_flow(export("S", session_id=session), now),
        "cites O's permit": h.governed_flow(
            export("S", cited_permit_event=o_run.get("gar_id")), now),
        "asserts O's authority": h.governed_flow(
            export("S", asserted_authority="approved by O"), now),
    }
    # S presents O's own ECC directly at the boundary (cross-agent redemption).
    launder["presents O's ECC"] = h.present(
        o_run["ecc"], now, "S", export("S")) if o_run.get("ecc") else {"admitted": False}

    # ---- Part B, step 5: every EXECUTION_AUTHORIZED attributable to its own subject.
    attributable = True
    for ev in _events(h, "EXECUTION_AUTHORIZED"):
        subject = ev["event.subject_id"]
        op = ev["event.action_spec"]
        own = h.surface.scope_of(subject)
        held, _ = (own.permits(op, now) if own else (False, "no role"))
        if not held:
            # Admissible only if a delegation recorded on this very event covers it.
            chain = ev.get("event.delegation_chain") or []
            covered = any(op["action_class"] in hop["scope"]["action_classes"]
                          and op["target"] in hop["scope"]["targets"]
                          for hop in chain)  # scope as recorded, §L.4
            if not covered:
                attributable = False

    all_widenings_denied = all(
        r.get("outcome") in ("REJECTED", "DENIED") and not r.get("admitted")
        for r in widenings.values())
    no_ecc_for_widening = all(
        _events(h, "ECC_COMPILED", r["gar_id"]) == []
        for r in widenings.values() if r.get("gar_id"))
    all_launder_denied = all(not r.get("admitted", False) for r in launder.values())
    delegated_events = [e for e in h.c5.events
                        if e.get("event.delegation_chain") is not None]

    checks = {
        "1 step 1 admitted (test is non-vacuous)": step1.get("admitted") is True,
        "2 every widening token fails deny, no ECC":
            all_widenings_denied and no_ecc_for_widening,
        "3 every laundering arrangement fails deny": all_launder_denied,
        "4 every execution attributable to its own subject": attributable,
        "5 delegated actions carry event.delegation_chain": len(delegated_events) > 0,
        "6 every rejection records subject and a typed reason":
            all(e.get("event.rejection_reason") and e.get("event.subject_id")
                for e in _events(h, "ADMISSION_REJECTED")),
        "7 chain integrity": h.c5.verify()[0],
    }
    ok = all(checks.values())
    failed = [k for k, v in checks.items() if not v]
    return ("NT-008 authority non-expansion (I8 clauses a and b)", ok,
            "step1=%s widenings=%s laundering=%s%s"
            % (step1.get("admitted"),
               dict((k, v.get("rejection_reason") or v.get("outcome"))
                    for k, v in widenings.items()),
               dict((k, v.get("admitted", False)) for k, v in launder.items()),
               "" if ok else " FAILED: %s" % failed)), h, checks


# ==================================================== Evidence Pack
def _record(test_id, name, h, checks, setup, inputs):
    return NegativeTestResult(
        test_id, name, setup, inputs,
        expected=dict((k, "hold") for k in checks),
        actual=dict((k, "hold" if v else "DOES NOT HOLD") for k, v in checks.items()),
        passed=all(checks.values()),
        event_ids=[e["event.id"] for e in h.c5.events],
        notes="Executed by the CROA Minimal Reference Harness against its own C5 record. "
              "Chain integrity and decision correlation verified after execution.")


def build_evidence_pack(path=None):
    """Run NT-005, NT-006 and NT-008 and assemble the Appendix Q Part 1 pack.

    Each test runs against its own harness, because their invariant registries differ --
    an E3 SQL analyzer, a cumulative export counter, and a delegation role model are three
    different deployments, not three phases of one. The pack therefore reports each test's
    own C5 record, and the worked examples come from the run with the widest event
    coverage.
    """
    (n5, ok5, d5), h5, c5 = nt005_ambiguous_e3_denied()
    (n6, ok6, d6), h6, c6 = nt006_trajectory_alert_then_deny()
    (n8, ok8, d8), h8, c8 = nt008_authority_non_expansion()

    widest = max((h5, h6, h8), key=lambda h: len(set(
        e["event.type"] for e in h.c5.events)))
    pack = EvidencePack(widest.c5, deployment="croa-mrh-demonstrator",
                        profile="CROA Core (Appendix K)")
    pack.add_test(_record(
        "NT-005", "Ambiguous E3 Verdict Denied", h5, c5,
        {"e3_analyzer": "sql-phi-analyzer-v2.1.3 (pinned)",
         "invariant": "I-PHI-SQL-001", "fail_deny_active": True},
        {"action_class": "sql.execute", "expected_analyzer_response": "AMBIGUOUS"}))
    pack.add_test(_record(
        "NT-006", "Progressive Data Export Trajectory Alert and Subsequent Deny", h6, c6,
        {"invariant": "I-DATA-EXP-001", "trajectory_profile": "TP-C",
         "alert_threshold": 450, "hard_limit": 500},
        {"requests": "5 x 90 distinct subjects, then 1 x 60"}))
    pack.add_test(_record(
        "NT-008", "Authority Non-Expansion", h8, c8,
        {"subjects": "O {data.export(billing), report.generate}, S {report.generate}",
         "delegation_implemented": True},
        {"part_a": "widening on action_class, target, parameters, window, depth",
         "part_b": "four laundering arrangements"}))

    if path:
        pack.write(path)
    return pack, [(n5, ok5, d5), (n6, ok6, d6), (n8, ok8, d8)]


# The three tests, in the scenario-runner shape used by mrh/scenarios.py.
def nt005():
    return nt005_ambiguous_e3_denied()[0]


def nt006():
    return nt006_trajectory_alert_then_deny()[0]


def nt008():
    return nt008_authority_non_expansion()[0]


def evidence_pack_scenario():
    pack, _ = build_evidence_pack()
    built = pack.build()
    v = built["verification"]
    ok = (built["negative_test_summary"]["failed"] == 0
          and v["chain_integrity"]["ok"] and v["decision_correlation"]["ok"]
          and len(built["worked_examples"]) >= 6)
    return ("Evidence Pack assembled from the C5 record (Appendix Q Part 1)", ok,
            "tests=%d/%d worked_examples=%d event_types=%d"
            % (built["negative_test_summary"]["passed"],
               built["negative_test_summary"]["executed"],
               len(built["worked_examples"]), len(built["event_coverage"])))
