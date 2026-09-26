"""Evidence ladder. Agent prose cannot skip a rung."""

def error_class_of(excerpt: str) -> str {
    text = excerpt.lower();
    if "heap-buffer-overflow" in text {
        return "heap-buffer-overflow";
    }
    if "stack-buffer-overflow" in text {
        return "stack-buffer-overflow";
    }
    if "global-buffer-overflow" in text {
        return "global-buffer-overflow";
    }
    if "signed integer overflow" in text {
        return "signed-integer-overflow";
    }
    if "undefined-behavior" in text or "undefined behavior" in text {
        return "undefined-behavior";
    }
    return "";
}

def confirmed_claim(error_class: str, frame: str, sanitizer: str) -> str {
    where = frame if frame != "" else "an unknown frame";
    tool = sanitizer if sanitizer != "" else "a sanitizer";
    return (
        f"Deterministic {error_class} reported by the {tool} sanitizer in {where}. "
        + "The minimized input still triggers the same signature. "
        + "No control-flow hijack was demonstrated."
    );
}

def classify_evidence(exit_type: str, sanitizer: str, frame: str, excerpt: str, invariant: str,
                      behavior_new: int, reproducible: bool, replay_matches: bool, minimized: bool,
                      narrow_supported: bool, broad_rejected: bool, narrow_text: str) -> dict {
    error_class = error_class_of(excerpt);
    base = {
        "error_class": error_class,
        "reproducible": reproducible and replay_matches,
        "minimized": minimized,
    };
    if exit_type == "TIMEOUT" {
        if reproducible and replay_matches {
            base["classification"] = "REPRODUCIBLE_FAILURE";
            base["claim"] = "Input exceeded the execution deadline on replay. This records a hang, not a demonstrated memory-safety bug.";
        } else {
            base["classification"] = "SUSPICIOUS_DIVERGENCE";
            base["claim"] = "Input exceeded the execution deadline once. Reproduction has not confirmed the hang.";
        }
        return base;
    }
    if exit_type == "SANITIZER" or exit_type == "CRASH" {
        if not reproducible or not replay_matches {
            base["classification"] = "CAPTURED";
            base["claim"] = "Abnormal exit was captured. Replay has not reproduced the same signature, so it is not a confirmed failure.";
            base["reproducible"] = False;
            return base;
        }
        where = frame if frame != "" else "an unidentified frame";
        kind = sanitizer if sanitizer != "" else exit_type.lower();
        base["classification"] = "REPRODUCIBLE_FAILURE";
        base["claim"] = f"Reproducible {kind} exit in {where}.";
        if narrow_supported and narrow_text != "" {
            base["classification"] = "SECURITY_HYPOTHESIS";
            base["claim"] = narrow_text;
        }
        if narrow_supported and minimized and error_class != "" and broad_rejected {
            base["classification"] = "CONFIRMED_SECURITY_FINDING";
            base["claim"] = confirmed_claim(error_class, frame, sanitizer);
        }
        return base;
    }
    if invariant != "" {
        base["classification"] = "SUSPICIOUS_DIVERGENCE";
        base["claim"] = f"Invariant {invariant} fired and the process exited normally. That is a behavioral divergence, not by itself a memory-safety failure.";
        return base;
    }
    if behavior_new > 0 {
        base["classification"] = "NOVEL_BEHAVIOR";
        base["claim"] = "This input produced a behavioral key that earlier inputs in the campaign had not.";
        return base;
    }
    base["classification"] = "UNREMARKABLE";
    base["claim"] = "Execution added neither a new behavioral key nor an abnormal exit.";
    return base;
}

test "anomaly does not become a confirmed finding" {
    novel = classify_evidence("NORMAL", "", "", "", "", 2, False, False, False, False, False, "");
    assert novel["classification"] == "NOVEL_BEHAVIOR";
    diverged = classify_evidence("NORMAL", "", "", "", "data_before_auth", 1, False, False, False, False, False, "");
    assert diverged["classification"] == "SUSPICIOUS_DIVERGENCE";
    assert "memory-safety failure" in diverged["claim"];
}

test "unreproduced crash stays captured" {
    cap = classify_evidence("SANITIZER", "address", "consume_length", "heap-buffer-overflow", "", 0, False, False, False, True, True, "bounds");
    assert cap["classification"] == "CAPTURED";
    assert cap["reproducible"] == False;
}

test "confirmation requires minimization, error class, and a rejected overclaim" {
    hyp = "The length field is trusted and consume_length reads past the input object.";
    partial = classify_evidence(
        "SANITIZER", "address", "consume_length", "heap-buffer-overflow", "", 0,
        True, True, False, True, True, hyp
    );
    assert partial["classification"] == "SECURITY_HYPOTHESIS";
    full = classify_evidence(
        "SANITIZER", "address", "consume_length", "ERROR: AddressSanitizer: heap-buffer-overflow", "", 0,
        True, True, True, True, True, hyp
    );
    assert full["classification"] == "CONFIRMED_SECURITY_FINDING";
    assert "heap-buffer-overflow" in full["claim"];
    assert "No control-flow hijack was demonstrated." in full["claim"];
    assert "CVE" not in full["claim"];
    missing_reject = classify_evidence(
        "SANITIZER", "address", "consume_length", "heap-buffer-overflow", "", 0,
        True, True, True, True, False, hyp
    );
    assert missing_reject["classification"] == "SECURITY_HYPOTHESIS";
}
