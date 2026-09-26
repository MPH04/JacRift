"""Behavioral novelty, independent of SanitizerCoverage edge counts.

A key is new when this campaign has not observed that transition, semantic
label, invariant, or opcode class. The fingerprint hashes the whole event
sequence. Surprise is the sum of 1/(1+prior) over tracked events and is not
a vulnerability score.
"""

def _mask64(value: int) -> int {
    return value & ((1 << 64) - 1);
}

def fnv_update(h: int, text: str) -> int {
    for ch in text {
        h = _mask64((h ^ ord(ch)) * 1099511628211);
    }
    return h;
}

def fingerprint_events(events: list) -> int {
    h = 14695981039346656037;
    for ev in events {
        for part in [ev["kind"], ev["a"], ev["b"]] {
            h = fnv_update(h, part);
            h = _mask64((h ^ ord("|")) * 1099511628211);
        }
        h = _mask64((h ^ ord("\n")) * 1099511628211);
    }
    return h;
}

def fingerprint_hex(events: list) -> str {
    return f"{fingerprint_events(events):016x}";
}

def behavior_key(ev: dict) -> str {
    kind = ev["kind"];
    if kind != "transition" and kind != "semantic" and kind != "invariant" and kind != "op" {
        return "";
    }
    b = "-";
    if kind != "op" {
        b = ev["b"];
    }
    return kind + ":" + ev["a"] + ":" + b;
}

obj BehaviorBook {
    has counts: dict;

    def observe(events: list) -> dict {
        new_keys = [];
        surprise = 0.0;
        for ev in events {
            key = behavior_key(ev);
            if key == "" {
                continue;
            }
            prior = 0;
            if key in self.counts {
                prior = self.counts[key];
            }
            surprise += 1.0 / (1.0 + prior);
            if prior == 0 {
                new_keys.append(key);
            }
            nxt = prior + 1;
            if nxt > 1000000 {
                nxt = 1000000;
            }
            self.counts[key] = nxt;
        }
        return {
            "new_keys": new_keys,
            "new_count": len(new_keys),
            "surprise": surprise,
            "fingerprint": fingerprint_hex(events),
            "known_keys": len(self.counts),
        };
    }
}

def fresh_book() -> BehaviorBook {
    return BehaviorBook(counts={});
}

def first_invariant(events: list) -> str {
    for ev in events {
        if ev["kind"] == "invariant" {
            return ev["a"];
        }
    }
    return "";
}

def note_labels(events: list) -> list {
    found = [];
    for ev in events {
        if ev["kind"] == "semantic" and ev["a"] == "note" {
            if ev["b"] not in found {
                found.append(ev["b"]);
            }
        }
    }
    return found;
}

test "same coverage shape can still be behavior-novel" {
    book = fresh_book();
    first = [
        {"kind": "op", "a": "magic", "b": "-"},
        {"kind": "op", "a": "note", "b": "-"},
        {"kind": "semantic", "a": "note", "b": "alpha"},
    ];
    second = [
        {"kind": "op", "a": "magic", "b": "-"},
        {"kind": "op", "a": "note", "b": "-"},
        {"kind": "semantic", "a": "note", "b": "beta"},
    ];
    a = book.observe(first);
    b = book.observe(second);
    assert a["new_count"] == 3;
    assert b["new_count"] == 1;
    assert b["new_keys"] == ["semantic:note:beta"];
    assert a["fingerprint"] != b["fingerprint"];
    again = book.observe(second);
    assert again["new_count"] == 0;
    assert again["surprise"] < b["surprise"];
}

test "fingerprint is stable and 16 hex chars" {
    events = [{"kind": "reject", "a": "magic", "b": "-"}];
    one = fingerprint_hex(events);
    two = fingerprint_hex(events);
    assert one == two;
    assert len(one) == 16;
}
