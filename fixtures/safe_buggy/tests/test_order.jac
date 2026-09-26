"""TEST / DEMONSTRATION FIXTURE. The assertion describes the intended gate."""

import from checkout.order_graph { apply_transition }

test "completion waits for verification" {
    nxt = apply_transition("PENDING", False, "complete");
    assert nxt != "COMPLETE";
}
