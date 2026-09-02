"""Wires the components together and drives a governed action through the gauntlet:
C3 -> C2 -> C7 -> C6, recording every decision in C5.

September 2026 — corrected after an independent audit. See mrh/components.py and
spec/known-defects-harness.md in the CROA repository.
"""
from .audit import AuditStore
from .components import (
    AuthorizationSpent,
    ContractCompiler,
    ExecutionFirewall,
    ExecutionGovernor,
    PathResolver,
    PolicyAuthority,
)


class Harness:
    def __init__(self):
        golden = {"orders-db", "crm", "billing", "reporting-api"}
        self.c1 = PolicyAuthority(approved_export_targets={"crm"})
        self.c3 = PathResolver(golden)
        self.c2 = ExecutionGovernor(self.c1)
        self.c7 = ContractCompiler(self.c1)
        self.c6 = ExecutionFirewall()
        self.c5 = AuditStore()

    def governed_flow(self, action, now, authorization=None):
        sid = action["subject_id"]
        session_id = action.get("session_id", "sess-" + sid)

        if not self.c3.resolve(action["target"]):
            self.c5.emit("CONTEXT_FAILURE", "C3", sid, **{
                "event.session_id": session_id,
                "event.action_spec": action,
                "golden_record_check": "NOT_FOUND",
                "c2_invoked": False,
            })
            return {"outcome": "BLOCKED", "stage": "C3", "reason": "context_failure"}

        decision, reason = self.c2.evaluate(action, authorization, now)
        if decision == "DENY":
            self.c5.emit("DENY", "C2", sid, **{
                "event.session_id": session_id,
                "event.action_spec": action,
                "event.decision_basis": "DENY",
                "event.deny_reason": reason,
            })
            return {"outcome": "DENIED", "stage": "C2", "reason": reason}

        permit_fields = {
            "event.session_id": session_id,
            "event.action_spec": action,
            "event.decision_basis": decision,
        }
        if decision == "PERMIT_WITH_AUTHORIZATION":
            permit_fields["event.auth_id"] = authorization["auth_id"]
        permit_ev = self.c5.emit("PERMIT", "C2", sid, **permit_fields)

        # FIX H-01. A PERMIT_WITH_AUTHORIZATION decision does not spend the
        # authorization; compilation does, atomically. A second compilation against the
        # same authorization fails here and produces no commitment.
        try:
            cc = self.c7.compile(
                action, now, permit_event_id=permit_ev["event.id"],
                authorization=(authorization if decision == "PERMIT_WITH_AUTHORIZATION" else None),
            )
        except AuthorizationSpent as exc:
            self.c5.emit("COMPILATION_REFUSED", "C7", sid, **{
                "event.session_id": session_id,
                "event.permit_event_id": permit_ev["event.id"],
                "event.action_spec": action,
                "event.deny_reason": str(exc),
            })
            return {"outcome": "DENIED", "stage": "C7", "reason": str(exc)}

        self.c5.emit("CC_COMPILED", "C7", sid, **{
            "event.session_id": session_id,
            "event.cc_id": cc["cc.id"],
            "event.permit_event_id": permit_ev["event.id"],
            "event.action_spec": action,
        })
        return {
            "outcome": "COMPILED", "stage": "C7", "cc": cc, "decision_basis": decision,
            **self.present(cc, now, sid, action),
        }

    def present(self, cc, now, subject_id, operation=None):
        """Present a Compiled Commitment (or None) at the execution boundary (C6).

        FIX H-02. `subject_id` is the *authenticated* identity of whoever is presenting,
        and `operation` is what they are actually asking to perform. Both are handed to
        C6, which compares them against the signed commitment. Nothing written to C5
        comes from the caller any more: the subject, the action and the session all come
        from the validated commitment.
        """
        if operation is None and cc is not None:
            operation = cc["action"]

        status, br = self.c6.redeem(cc, now, subject_id, operation)

        if status == "AUTHORIZED":
            fields = {
                "event.cc_id": cc["cc.id"],
                "event.permit_event_id": cc["permit_event_id"],
                "event.action_spec": cc["action"],
                "event.session_id": cc["action"].get("session_id", "sess-" + cc["subject"]),
            }
            auth_ref = cc.get("auth_ref")
            if auth_ref is not None:
                self.c1.redeem_authorization(auth_ref)
                fields["event.auth_id"] = auth_ref
            # The subject recorded is the commitment's, never the caller's.
            self.c5.emit("EXECUTION_AUTHORIZED", "C6", cc["subject"], **fields)
            return {"admitted": True}

        self.c5.emit("EXECUTION_BLOCKED", "C6", subject_id, **{
            "event.block_reason": br,
            "event.cc_id": (cc or {}).get("cc.id"),
        })
        return {"admitted": False, "block_reason": br}
