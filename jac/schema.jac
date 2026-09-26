"""vectorrift.execution.v1 validation. Reject the line rather than guessing."""

import json;

import from text { bound_text, sanitize_token }

def schema_error(reason: str) -> dict {
    return {"ok": False, "error": reason, "event": {}};
}

def as_int(value: any, lo: int, hi: int) -> int | None {
    if type(value) is bool or type(value) is not int {
        return None;
    }
    if value < lo or value > hi {
        return None;
    }
    return value;
}

def parse_execution(line: str) -> dict {
    if len(line) > 262144 {
        return schema_error("line_too_large");
    }
    try {
        raw = json.loads(line);
    } except Exception {
        return schema_error("malformed_json");
    }
    if type(raw) is not dict {
        return schema_error("not_object");
    }
    if raw.get("schema") != "vectorrift.execution.v1" {
        return schema_error("schema");
    }
    exit_type = raw.get("exit_type");
    allowed = ["NORMAL", "CRASH", "TIMEOUT", "SANITIZER", "ENGINE"];
    if exit_type not in allowed {
        return schema_error("exit_type");
    }
    events = raw.get("events");
    if type(events) is not list or len(events) > 64 {
        return schema_error("events");
    }
    clean_events = [];
    for ev in events {
        if type(ev) is not dict {
            return schema_error("event_shape");
        }
        clean_events.append({
            "kind": sanitize_token(str(ev.get("kind", "")), 48),
            "a": sanitize_token(str(ev.get("a", "")), 48),
            "b": sanitize_token(str(ev.get("b", "")), 48),
        });
    }
    input_id = str(raw.get("input_id", ""));
    if len(input_id) < 8 or len(input_id) > 64 {
        return schema_error("input_id");
    }
    exec_index = as_int(raw.get("exec_index", 0), 0, 10000000);
    new_edges = as_int(raw.get("new_edges", 0), 0, 1000000);
    hit_edges = as_int(raw.get("hit_edges", 0), 0, 1000000);
    edges_seen = as_int(raw.get("edges_seen_total", 0), 0, 1000000);
    guards = as_int(raw.get("guards", 0), 0, 1000000);
    behavior_new = as_int(raw.get("behavior_new", 0), 0, 10000);
    input_len = as_int(raw.get("input_len", 0), 0, 1048576);
    execution_us = as_int(raw.get("execution_us", 0), 0, 600000000);
    signal = as_int(raw.get("signal", 0), 0, 128);
    if exec_index is None or new_edges is None or behavior_new is None or input_len is None {
        return schema_error("numeric");
    }
    if hit_edges is None or edges_seen is None or guards is None or execution_us is None or signal is None {
        return schema_error("numeric");
    }
    event = {
        "schema": "vectorrift.execution.v1",
        "input_id": sanitize_token(input_id, 64),
        "parent_id": sanitize_token(str(raw.get("parent_id", "")), 64),
        "mutation": sanitize_token(str(raw.get("mutation", "")), 32),
        "seed": as_int(raw.get("seed", 0), 0, 2 ** 31 - 1) or 0,
        "exec_index": exec_index,
        "input_len": input_len,
        "input_hex": bound_text(str(raw.get("input_hex", "")), 256),
        "exit_type": exit_type,
        "sanitizer": sanitize_token(str(raw.get("sanitizer", "")), 24),
        "signal": signal,
        "new_edges": new_edges,
        "hit_edges": hit_edges,
        "edges_seen_total": edges_seen,
        "guards": guards,
        "behavior_new": behavior_new,
        "fingerprint": sanitize_token(str(raw.get("fingerprint", "")), 32),
        "execution_us": execution_us,
        "completed": bool(raw.get("completed", False)),
        "stderr_truncated": bool(raw.get("stderr_truncated", False)),
        "events_truncated": bool(raw.get("events_truncated", False)),
        "frame": sanitize_token(str(raw.get("frame", "")), 96),
        "stderr_excerpt": bound_text(str(raw.get("stderr_excerpt", "")), 2000),
        "events": clean_events,
        "saved": bool(raw.get("saved", False)),
    };
    return {"ok": True, "error": "", "event": event};
}

test "schema rejects garbage and keeps a real shape" {
    bad = parse_execution("not-json");
    assert bad["ok"] == False;
    assert bad["error"] == "malformed_json";
    huge = parse_execution("{" + ("\"" * 300000));
    assert huge["ok"] == False;
    sample = "{\"schema\":\"vectorrift.execution.v1\",\"input_id\":\"abcdef0123456789\",\"parent_id\":\"\",\"mutation\":\"seed\",\"seed\":1,\"exec_index\":0,\"input_len\":2,\"input_hex\":\"5652\",\"exit_type\":\"NORMAL\",\"sanitizer\":\"\",\"signal\":0,\"new_edges\":3,\"hit_edges\":3,\"edges_seen_total\":3,\"guards\":10,\"behavior_new\":1,\"fingerprint\":\"abc\",\"execution_us\":20,\"completed\":true,\"stderr_truncated\":false,\"events_truncated\":false,\"frame\":\"\",\"stderr_excerpt\":\"ok\",\"events\":[{\"kind\":\"op\",\"a\":\"magic\",\"b\":\"-\"}],\"saved\":true}";
    good = parse_execution(sample);
    assert good["ok"] == True;
    assert good["event"]["exit_type"] == "NORMAL";
    assert good["event"]["events"][0]["kind"] == "op";
    injected = parse_execution(sample.replace("magic", "../x<script>"));
    assert injected["ok"] == True;
    assert "<" not in injected["event"]["events"][0]["a"];
}
