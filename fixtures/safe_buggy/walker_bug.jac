"""TEST / DEMONSTRATION FIXTURE. Walker reports completion on an unverified gate."""

node Gate {
    has verified: bool;
}

walker Advance {
    has action: str;

    can enter with Gate entry {
        if self.action == "complete" and not here.verified {
            print("JACRIFT_EVENT {\"category\":\"WALKER_FAILURE\",\"file\":\"walker_bug.jac\",\"line\":10,\"marker\":\"walker_complete_before_verification\"}");
        }
    }
}

with entry {
    gate = Gate(verified=False);
    root ++> gate;
    gate spawn Advance(action="complete");
}
