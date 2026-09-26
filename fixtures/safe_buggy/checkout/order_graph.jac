"""TEST / DEMONSTRATION FIXTURE. Completion does not wait for verification."""

def apply_transition(status: str, verified: bool, action: str) -> str {
    if action == "complete" {
        if not verified {
            print("JACRIFT_EVENT {\"category\":\"STATE_INVARIANT_FAILURE\",\"file\":\"checkout/order_graph.jac\",\"line\":6,\"marker\":\"complete_before_verification\"}");
        }
        return "COMPLETE";
    }
    if action == "verify" {
        return "VERIFIED";
    }
    return status;
}
