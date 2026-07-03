"""Wires the components together and drives a governed action through the gauntlet:
C3 -> C2 -> C7 -> C6, recording every decision in C5."""
from .audit import AuditStore
from .components import PolicyAuthority, PathResolver, ExecutionGovernor, ContractCompiler, ExecutionFirewall

class Harness:
    def __init__(self):
        golden = {"orders-db", "crm", "billing", "reporting-api"}
        self.c1 = PolicyAuthority(approved_export_targets={"crm"})
        self.c3 = PathResolver(golden)
        self.c2 = ExecutionGovernor(self.c1)
        self.c7 = ContractCompiler()
        self.c6 = ExecutionFirewall()
        self.c5 = AuditStore()

    def governed_flow(self, action, now, authorization=None):
        sid = action["subject_id"]
        if not self.c3.resolve(action["target"]):
            self.c5.emit("CONTEXT_FAILURE", "C3", sid,
                         **{"event.action_spec": action, "golden_record_check": "NOT_FOUND", "c2_invoked": False})
            return {"outcome": "BLOCKED", "stage": "C3", "reason": "context_failure"}
        decision, reason = self.c2.evaluate(action, authorization, now)
        if decision == "DENY":
            self.c5.emit("DENY", "C2", sid,
                         **{"event.action_spec": action, "event.decision_basis": "DENY", "event.deny_reason": reason})
            return {"outcome": "DENIED", "stage": "C2", "reason": reason}
        permit_fields = {"event.action_spec": action, "event.decision_basis": decision}
        if decision == "PERMIT_WITH_AUTHORIZATION":
            permit_fields["event.auth_id"] = authorization["auth_id"]   # C5 records the authorization identifier (white paper 3.7)
        self.c5.emit("PERMIT", "C2", sid, **permit_fields)
        cc = self.c7.compile(action, now,
                             authorization=(authorization if decision == "PERMIT_WITH_AUTHORIZATION" else None))
        self.c5.emit("CC_COMPILED", "C7", sid, **{"event.cc_id": cc["cc.id"]})
        return {"outcome": "COMPILED", "stage": "C7", "cc": cc, "decision_basis": decision,
                **self.present(cc, now, sid)}

    def present(self, cc, now, sid):
        """Present a Compiled Commitment (or None) at the execution boundary (C6)."""
        status, br = self.c6.redeem(cc, now)
        if status == "AUTHORIZED":
            fields = {"event.cc_id": cc["cc.id"]}
            auth_ref = cc.get("auth_ref")
            if auth_ref is not None:
                # A governed exception has now backed an admitted execution: spend it (single-use).
                self.c1.redeem_authorization(auth_ref)
                fields["event.auth_id"] = auth_ref
            self.c5.emit("EXECUTION_AUTHORIZED", "C6", sid, **fields)
            return {"admitted": True}
        self.c5.emit("EXECUTION_BLOCKED", "C6", sid,
                     **{"event.block_reason": br, "event.cc_id": (cc or {}).get("cc.id")})
        return {"admitted": False, "block_reason": br}
