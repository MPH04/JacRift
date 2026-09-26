"""Structured next experiments. Agents request these; they are not shell strings."""

def stretch_length(data: bytes) -> bytes {
    if len(data) < 4 {
        return b"";
    }
    raw = bytearray(data);
    i = 2;
    while i < len(raw) - 2 {
        if raw[i] == 76 {
            raw[i + 1] = 2;
            raw[i + 2] = 0;
            return bytes(raw);
        }
        i += 1;
    }
    return b"";
}

def overflow_scale() -> bytes {
    return bytes([0x56, 0x52, 0x53, 0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff]);
}

def note_probe(index: int) -> bytes {
    return bytes([0x56, 0x52, 0x4e, index & 7]);
}

def divergence_probe() -> bytes {
    return bytes([0x56, 0x52, 0x44, 0x01]);
}

def plan_experiments(seen_address: bool, seen_undefined: bool, seen_invariant: bool, note_count: int,
                     unreproduced: int, unminimized: int) -> list {
    plan = [];
    if unreproduced > 0 {
        plan.append({
            "id": "reproduce",
            "reason": "A failure was captured and has not been replayed.",
            "expects": "The same exit type, sanitizer, and frame.",
        });
    }
    if unminimized > 0 {
        plan.append({
            "id": "minimize",
            "reason": "A reproduced failure still has a larger input than necessary.",
            "expects": "A shorter input that preserves the failure signature.",
        });
    }
    if note_count < 8 {
        plan.append({
            "id": "note_sweep",
            "reason": "Semantic note labels can change with no new SanitizerCoverage edge.",
            "expects": "At least one input with behavior_new > 0 and new_edges == 0.",
        });
    }
    if not seen_address {
        plan.append({
            "id": "length_past_end",
            "reason": "Seeds exercise the length opcode but have not produced an address-sanitizer report.",
            "expects": "A heap-buffer-overflow in consume_length.",
        });
    }
    if not seen_undefined {
        plan.append({
            "id": "scale_overflow",
            "reason": "The scale opcode has not produced an undefined-behavior report.",
            "expects": "A signed integer overflow diagnostic.",
        });
    }
    if not seen_invariant {
        plan.append({
            "id": "data_before_auth",
            "reason": "No input has emitted the data-before-auth invariant.",
            "expects": "A normal exit that still reports the invariant.",
        });
    }
    return plan;
}

test "length stretch targets the length field" {
    seed = bytes([0x56, 0x52, 0x4c, 0x00, 0x04, 0x41, 0x42, 0x43, 0x44]);
    stretched = stretch_length(seed);
    assert stretched[2] == 76;
    assert stretched[3] == 2;
    assert stretched[4] == 0;
    assert len(stretched) == len(seed);
    assert stretch_length(b"VR") == b"";
}

test "planner asks for the missing experiment" {
    plan = plan_experiments(False, True, True, 8, 0, 0);
    ids = [item["id"] for item in plan];
    assert ids == ["length_past_end"];
    full = plan_experiments(True, True, True, 8, 1, 1);
    assert full[0]["id"] == "reproduce";
    assert full[1]["id"] == "minimize";
}
