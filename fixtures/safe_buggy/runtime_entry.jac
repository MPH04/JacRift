"""TEST / DEMONSTRATION FIXTURE. Runs the order transition from a JSON input."""

import json;
import os;

import from checkout.order_graph { apply_transition }

with entry {
    raw = os.environ.get("JACRIFT_INPUT", "");
    verified = False;
    action = "complete";
    if raw != "" {
        data = json.loads(raw);
        verified = bool(data.get("verified", False));
        action = str(data.get("action", "complete"));
    }
    apply_transition("PENDING", verified, action);
}
