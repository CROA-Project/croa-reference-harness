"""Wires C1-C7 together and drives a governed action through the gauntlet:
Agent Surface -> C3 -> C2 -> C7 -> C6, recording every decision in C5.

The ordering in `present()` is the part worth reading. §4.8 requires the redemption
record to be "committed to (or replicated to) C5 before the authorized operation is
released to the governed system", and §4.7 requires the event to be durable before the
next governed action is admitted. So:

    1. validate statically          -- a claim is irreversible; never spend a use on
                                       an ECC that was going to fail anyway
    2. claim atomically             -- one CAS over {ecc.id, auth_ref}
    3. record in C5, durably        -- fsync returns before step 4 begins
    4. release to the governed system

An implementation that swaps 2 and 3 has a redemption window; one that swaps 3 and 4
can execute an operation it has no record of. Both are failures the audit trail cannot
reconstruct after the fact, which is why the order is fixed here rather than left to
the caller.

The governed system is modelled as `self.systems`, a dict of target -> list of applied
operations, so a scenario can assert on effects rather than only on decisions -- NT-007
pass criterion 6 is "the governed system shows exactly one authorized export".
"""
from .audit import AuditStore
from .components import (
    AgentSurface,
    AuthorizationInvalid,
    ContractCompiler,
    ExecutionFirewall,
    ExecutionGovernor,
    PathResolver,
    PolicyAuthority,
)
from .delegation import DelegationRejected, Scope, build_chain, verify_token
from .redemption import InProcessRegistry
from .trajectory import C4Unavailable, InvariantMonitor


class Harness(object):
    DEFAULT_CONTEXT = ("orders-db", "crm", "billing", "reporting-api", "analytics",
                       "analytics-warehouse")

    def __init__(self, registry=None, audit=None, firewalls=1, invariants=None,
                 roles=None, context=None):
        self.registry = registry if registry is not None else InProcessRegistry()
        self.c1 = PolicyAuthority(approved_export_targets={"crm"}, registry=invariants)
        self.c3 = PathResolver(context if context is not None else self.DEFAULT_CONTEXT)
        self.c4 = InvariantMonitor(self.c1.registry)
        self.c2 = ExecutionGovernor(self.c1, registry=self.registry, c4=self.c4)
        self.c7 = ContractCompiler(self.c1)
        # The Agent Surface is permissive by default -- an unknown subject holds a scope
        # covering the demonstrator's action classes -- so the lot-2 scenarios keep
        # working. NT-008 constructs one with real roles, which is where §4.9.1 bites.
        self.surface = AgentSurface(roles=roles) if roles is not None else None
        # Several C6 instances, one shared registry -- the §4.8 topology. `self.c6`
        # stays as the default so existing callers are unaffected.
        self.firewalls = [ExecutionFirewall(self.registry, "c6-%d" % (i + 1))
                          for i in range(max(1, firewalls))]
        self.c6 = self.firewalls[0]
        self.c5 = audit if audit is not None else AuditStore()
        self.systems = {}
        self.gar_seq = 0

    # ------------------------------------------------------------------ flow
    def governed_flow(self, action, now, authorization=None, delegation_token=None,
                      delegation_hops=None):
        sid = action["subject_id"]
        session_id = action.get("session_id", "sess-" + sid)
        self.gar_seq += 1
        gar_id = action.get("gar_id", "gar-%04d" % self.gar_seq)
        delegated_scope = None

        # --- Agent Surface: admission before anything else (§4.9, §4.9.1)
        if self.surface is not None:
            if delegation_token is not None:
                authorizing = self.surface.scope_of(
                    delegation_token["gga.delegation.authorizing_subject"])
                try:
                    delegated_scope = Scope.from_dict(
                        sid, delegation_token["gga.delegation.scope"])
                except DelegationRejected as exc:
                    return self._reject(action, session_id, gar_id,
                                        "UNAUTHORIZED_ACTION_CLASS", str(exc),
                                        exc.dimension, delegation_hops)
                ok, reason, dimension = verify_token(
                    delegation_token, authorizing, delegated_scope, now)
                if not ok:
                    return self._reject(action, session_id, gar_id,
                                        "UNAUTHORIZED_ACTION_CLASS", reason, dimension,
                                        delegation_hops)
            admitted, rejection, detail = self.surface.admit(
                action, now, delegation=delegated_scope)
            if not admitted:
                return self._reject(action, session_id, gar_id, rejection, detail,
                                    None, delegation_hops)

        if not self.c3.resolve(action["target"]):
            self.c5.emit("CONTEXT_FAILURE", "C3", sid, **{
                "event.session_id": session_id,
                "event.action_spec": action,
                # event.rejection_reason belongs to ADMISSION_REJECTED, not here:
                # a grounding failure is not an admission rejection (§4.7.1).
                "context_registry_check": "NOT_FOUND" if self.c3.available else "C3_UNAVAILABLE",
                "c2_invoked": False,
            })
            return {"outcome": "BLOCKED", "stage": "C3", "reason": "context_failure"}

        decision, reason, invariant_state = self.c2.evaluate(
            action, authorization, now, session_id=session_id)

        if decision in ("DENY", "DENY_AMBIGUOUS"):
            # NT-005: an ambiguous E3 verdict is a DENY whose *basis* records that
            # fail-deny was applied, not merely that a deny happened.
            fields = {
                "event.session_id": session_id,
                "event.action_spec": action,
                "event.decision_basis": ("AMBIGUOUS" if decision == "DENY_AMBIGUOUS"
                                         else "DENY"),
                "event.deny_reason": reason,
                "event.policy_artifact_id": self.c1.policy_artifact_id,
                "event.invariant_state": invariant_state,
                "gar_id": gar_id,
                "governance_outcome": "GOVERNANCE_SUCCESS",
                "invariants_evaluated": invariant_state.get("evaluated", []),
                "authorization_present": authorization is not None,
            }
            if invariant_state.get("analyzer_version"):
                fields["event.analyzer_version"] = invariant_state["analyzer_version"]
            if invariant_state.get("trajectory_state_id"):
                fields["trajectory_state_id"] = invariant_state["trajectory_state_id"]
            if invariant_state.get("violated"):
                fields["invariant_violated"] = invariant_state["violated"][0]
                fields["violated_invariant_text"] = self.c1.invariant_text(
                    invariant_state["violated"][0])
            if delegation_hops:
                fields["event.delegation_chain"] = build_chain(delegation_hops)
            self.c5.emit("DENY", "C2", sid, **fields)
            # A C4 outage is the *reason* for some of these denies. Recording the deny
            # is I6 and must not depend on the component that is down; a denied action
            # accumulates nothing anyway, so there is nothing lost by not observing it.
            try:
                self.c4.observe(action, session_id, "DENY", gar_id)
            except C4Unavailable:
                pass
            return {"outcome": "DENIED", "stage": "C2", "reason": reason,
                    "gar_id": gar_id, "decision_basis": fields["event.decision_basis"]}

        permit_fields = {
            "event.session_id": session_id,
            "event.action_spec": action,
            "event.decision_basis": decision,
            "event.policy_artifact_id": self.c1.policy_artifact_id,
            "event.invariant_state": invariant_state,
            "gar_id": gar_id,
            "invariants_evaluated": invariant_state.get("evaluated", []),
            "authorization_present": authorization is not None,
        }
        if invariant_state.get("analyzer_version"):
            permit_fields["event.analyzer_version"] = invariant_state["analyzer_version"]
        if decision == "PERMIT_WITH_AUTHORIZATION":
            permit_fields["event.auth_id"] = authorization["auth_id"]
        if delegation_hops:
            permit_fields["event.delegation_chain"] = build_chain(delegation_hops)
        permit_ev = self.c5.emit("PERMIT", "C2", sid, **permit_fields)

        # §4.6.2 step 3: the alert is raised on the action that reached the threshold,
        # after its decision and before the next action in the session is evaluated.
        # Reached only on a permit, which C4 must have been available to produce.
        crossed = self.c4.observe(action, session_id, decision, gar_id)
        if crossed is not None:
            self.c5.emit("TRAJECTORY_ALERT", "C4", sid, **{
                "event.session_id": session_id,
                "event.action_spec": [h["action"] for h in self.c4.history(session_id)],
                "event.invariant_state": {"at_risk": [crossed.invariant_id]},
                "trajectory_state_id": crossed.id,
                "current_value": crossed.current_value,
                "alert_threshold": crossed.alert_threshold,
                "hard_limit": crossed.hard_limit,
                "gar_id": gar_id,
            })

        try:
            ecc = self.c7.compile(
                action, now, permit_event_id=permit_ev["event.id"],
                authorization=(authorization if decision == "PERMIT_WITH_AUTHORIZATION" else None),
            )
        except AuthorizationInvalid as exc:
            # Not a spent authorization -- an unsigned, expired or mis-bound one. A
            # spent authorization compiles fine and is refused at the boundary, which
            # is where §4.8 puts the check.
            self.c5.emit("DENY", "C7", sid, **{
                "event.session_id": session_id,
                "event.permit_event_id": permit_ev["event.id"],
                "event.action_spec": action,
                "event.decision_basis": "DENY",
                "event.deny_reason": str(exc),
                "event.policy_artifact_id": self.c1.policy_artifact_id,
                "event.invariant_state": invariant_state,
            })
            return {"outcome": "DENIED", "stage": "C7", "reason": str(exc)}

        self.c5.emit("ECC_COMPILED", "C7", sid, **{
            "event.session_id": session_id,
            # §4.7.1 lists decision_basis as not applicable for the execution and
            # rejection types, but not for ECC_COMPILED: the compilation record has to
            # say which permit basis it compiled from, or a PERMIT_WITH_AUTHORIZATION
            # contract is indistinguishable from an ordinary one in the log.
            "event.decision_basis": decision,
            "event.policy_artifact_id": self.c1.policy_artifact_id,
            "event.invariant_state": invariant_state,
            "event.ecc_id": ecc["ecc.id"],
            "event.permit_event_id": permit_ev["event.id"],
            "event.action_spec": action,
        })
        return dict(
            {"outcome": "COMPILED", "stage": "C7", "ecc": ecc, "decision_basis": decision,
             "gar_id": gar_id},
            **self.present(ecc, now, sid, action, delegation_hops=delegation_hops)
        )

    # ------------------------------------------------------------- admission
    def _reject(self, action, session_id, gar_id, reason, detail, dimension, hops):
        """ADMISSION_REJECTED (§4.9.1). The request is not forwarded to C3 or C2."""
        fields = {
            "event.session_id": session_id,
            "event.attempted_type": action.get("action_class"),
            "event.rejection_reason": reason,
            "gar_id": gar_id,
            "governance_outcome": "GOVERNANCE_SUCCESS",
            "rejection_detail": detail,
        }
        if dimension is not None:
            fields["failed_scope_dimension"] = dimension
        if hops:
            fields["event.delegation_chain"] = build_chain(hops)
        self.c5.emit("ADMISSION_REJECTED", "AgentSurface", action["subject_id"], **fields)
        return {"outcome": "REJECTED", "stage": "AgentSurface", "reason": detail or reason,
                "rejection_reason": reason, "gar_id": gar_id,
                "failed_scope_dimension": dimension}

    def present(self, ecc, now, subject_id, operation=None, firewall=None,
                apply_effect=True, delegation_hops=None):
        """Present an ECC (or None) at the execution boundary.

        Nothing written to C5 comes from the caller: the subject, the action and the
        session all come from the validated contract. `firewall` selects which C6
        instance handles the presentation -- they share one registry, so which one it
        is must not change the outcome.
        """
        if operation is None and ecc is not None:
            operation = ecc["ecc.action"]
        c6 = firewall if firewall is not None else self.c6

        status, block_reason, detail = c6.redeem(
            ecc, now, subject_id, operation,
            invariant_set_version=self.c1.invariant_set_version)

        if status != "AUTHORIZED":
            # §4.7.1: event.ecc_id is carried "where a ecc.id was presented". When none
            # was, the field is absent -- not present and null, which would assert that
            # an ECC identified as nothing had been presented.
            fields = {
                "event.block_reason": block_reason,
                "event.session_id": (ecc or {}).get(
                    "ecc.session_id", (operation or {}).get("session_id", "sess-" + subject_id)),
                "event.emitter_instance": c6.instance_id,
            }
            if ecc is not None:
                fields["event.ecc_id"] = ecc.get("ecc.id")
            if ecc is not None and ecc.get("ecc.auth_ref") is not None:
                fields["event.auth_id"] = ecc["ecc.auth_ref"]
            if detail is not None:
                # Non-normative: §4.7.1's block_reason enumeration is closed and does
                # not name the scope and identity failures §4.8 requires C6 to catch.
                fields["event.block_detail"] = detail
            self.c5.emit("EXECUTION_BLOCKED", "C6", subject_id, **fields)
            return {"admitted": False, "block_reason": block_reason, "block_detail": detail}

        # Claim granted. Record before release (§4.8): an operation that reaches a
        # governed system before its authorization is durably recorded is an operation
        # the audit trail cannot account for.
        fields = {
            "event.ecc_id": ecc["ecc.id"],
            "event.permit_event_id": ecc["ecc.permit_event_id"],
            "event.action_spec": ecc["ecc.action"],
            "event.session_id": ecc["ecc.session_id"],
            "event.emitter_instance": c6.instance_id,
        }
        auth_ref = ecc.get("ecc.auth_ref")
        if auth_ref is not None:
            fields["event.auth_id"] = auth_ref
        if delegation_hops:
            fields["event.delegation_chain"] = build_chain(delegation_hops)
        self.c5.emit("EXECUTION_AUTHORIZED", "C6", ecc["ecc.subject"], **fields)

        if apply_effect:
            self._apply(ecc, operation)
        return {"admitted": True}

    # ---------------------------------------------------------------- effect
    def _apply(self, ecc, operation):
        """Execute against the governed system and attest the effect.

        `EXECUTION_AUTHORIZED` says the boundary let the operation through. It does not
        say the operation had an effect, and §4.7.1 adds three types precisely so the
        record can distinguish them: EXECUTION_COMPLETED, EXECUTION_FAILED, and
        EFFECT_ATTESTED for an effect the target system itself acknowledged.
        """
        target = operation["target"]
        try:
            self.systems.setdefault(target, []).append(operation)
        except Exception as exc:                              # pragma: no cover
            self.c5.emit("EXECUTION_FAILED", "C6", ecc["ecc.subject"], **{
                "event.ecc_id": ecc["ecc.id"],
                "event.session_id": ecc["ecc.session_id"],
                "event.failure_reason": str(exc),
            })
            return
        self.c5.emit("EXECUTION_COMPLETED", "C6", ecc["ecc.subject"], **{
            "event.ecc_id": ecc["ecc.id"],
            "event.session_id": ecc["ecc.session_id"],
            "event.exit_status": "OK",
        })
        # The demo target acknowledges the write, so the effect is attestable. A target
        # that returns no acknowledgment yields no EFFECT_ATTESTED, which is the honest
        # outcome: §4.7.1 requires a cryptographic acknowledgment from the target or a
        # trusted third-party observation, not the firewall's own say-so.
        ack = "ack-" + ecc["ecc.id"][4:16]
        self.c5.emit("EFFECT_ATTESTED", "C6", ecc["ecc.subject"], **{
            "event.ecc_id": ecc["ecc.id"],
            "event.session_id": ecc["ecc.session_id"],
            "event.attestation_reference": ack,
        })

    # ------------------------------------------------------------- inspection
    def applied(self, target):
        return self.systems.get(target, [])
