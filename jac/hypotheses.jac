"""Hypothesis templates and the skeptic. A hypothesis is never an upgrade by itself."""

import from classify { error_class_of }

def propose_hypotheses(exit_type: str, sanitizer: str, invariant: str) -> list {
    found = [];
    if sanitizer == "address" or (exit_type == "SANITIZER" and sanitizer == "address") {
        found.append({
            "narrow": True,
            "text": "The length field is trusted and consume_length reads past the input object.",
        });
        found.append({
            "narrow": False,
            "text": "This input demonstrates arbitrary code execution.",
        });
    } elif sanitizer == "undefined" {
        found.append({
            "narrow": True,
            "text": "apply_scale multiplies signed 32-bit values that overflow.",
        });
        found.append({
            "narrow": False,
            "text": "This input demonstrates arbitrary code execution.",
        });
    } elif invariant == "auth_without_open" {
        found.append({
            "narrow": True,
            "text": "An authentication opcode was accepted before the session was open.",
        });
        found.append({
            "narrow": False,
            "text": "This divergence is memory corruption.",
        });
    } elif invariant == "data_before_auth" {
        found.append({
            "narrow": True,
            "text": "The parser accepts a data opcode before authentication.",
        });
        found.append({
            "narrow": False,
            "text": "This divergence is memory corruption.",
        });
    } elif exit_type == "CRASH" {
        found.append({
            "narrow": True,
            "text": "The process aborted without a sanitizer diagnostic.",
        });
        found.append({
            "narrow": False,
            "text": "This input demonstrates arbitrary code execution.",
        });
    }
    return found;
}

def review_hypothesis(text: str, exit_type: str, sanitizer: str, frame: str, excerpt: str, invariant: str) -> dict {
    lowered = text.lower();
    error_class = error_class_of(excerpt);
    if "arbitrary code" in lowered or "remote code" in lowered {
        return {
            "status": "contradicted",
            "reason": "No observation shows instruction-pointer control or a write primitive.",
        };
    }
    if "memory corruption" in lowered {
        if exit_type == "NORMAL" {
            return {
                "status": "contradicted",
                "reason": "The process exited normally, so this record does not show memory corruption.",
            };
        }
        return {
            "status": "unresolved",
            "reason": "The phrase is broader than the captured diagnostic.",
        };
    }
    if "out-of-bounds" in lowered or "reads past" in lowered or "length field" in lowered {
        frame_ok = "consume_length" in frame or "length" in frame;
        class_ok = error_class == "heap-buffer-overflow" or error_class == "stack-buffer-overflow" or error_class == "global-buffer-overflow";
        if sanitizer == "address" and frame_ok and class_ok {
            return {
                "status": "supported",
                "reason": "AddressSanitizer names a buffer overflow and the frame is the length consumer.",
            };
        }
        if sanitizer == "address" and frame_ok {
            return {
                "status": "unresolved",
                "reason": "The address sanitizer fired in the length consumer, but the overflow class string was not in the excerpt.",
            };
        }
        return {
            "status": "contradicted",
            "reason": "The sanitizer class and frame do not support an out-of-bounds read in consume_length.",
        };
    }
    if "signed" in lowered or "overflow" in lowered {
        frame_ok = "riftpacket" in frame or "apply_scale" in frame or "scale" in frame;
        if sanitizer == "undefined" and frame_ok and error_class == "signed-integer-overflow" {
            return {
                "status": "supported",
                "reason": "UndefinedBehaviorSanitizer reports a signed overflow at the scale site.",
            };
        }
        if sanitizer == "undefined" and frame_ok {
            return {
                "status": "unresolved",
                "reason": "An undefined-behavior report was captured, but the signed-overflow wording was not.",
            };
        }
        return {
            "status": "contradicted",
            "reason": "No undefined-behavior signed overflow matches this hypothesis.",
        };
    }
    if "before the session" in lowered or "auth_without_open" in lowered {
        if invariant == "auth_without_open" and exit_type == "NORMAL" {
            return {
                "status": "supported",
                "reason": "The target emitted invariant auth_without_open and then exited normally.",
            };
        }
        return {
            "status": "contradicted",
            "reason": "That authentication invariant was not observed on a normal exit.",
        };
    }
    if "before authentication" in lowered or "data_before_auth" in lowered {
        if invariant == "data_before_auth" and exit_type == "NORMAL" {
            return {
                "status": "supported",
                "reason": "The target emitted invariant data_before_auth and then exited normally.",
            };
        }
        return {
            "status": "contradicted",
            "reason": "That invariant was not observed on a normal exit.",
        };
    }
    if "without a sanitizer" in lowered {
        if exit_type == "CRASH" and sanitizer == "" {
            return {
                "status": "supported",
                "reason": "The child terminated by signal and no sanitizer diagnostic was captured.",
            };
        }
        return {
            "status": "contradicted",
            "reason": "A sanitizer diagnostic is present, or the process did not crash.",
        };
    }
    return {
        "status": "unresolved",
        "reason": "No skeptic rule confirms or rejects this wording.",
    };
}

def adjudicate(exit_type: str, sanitizer: str, frame: str, excerpt: str, invariant: str) -> list {
    reviewed = [];
    for hyp in propose_hypotheses(exit_type, sanitizer, invariant) {
        verdict = review_hypothesis(hyp["text"], exit_type, sanitizer, frame, excerpt, invariant);
        reviewed.append({
            "narrow": hyp["narrow"],
            "text": hyp["text"],
            "status": verdict["status"],
            "reason": verdict["reason"],
        });
    }
    return reviewed;
}

def narrow_supported_text(reviewed: list) -> str {
    for hyp in reviewed {
        if hyp["narrow"] and hyp["status"] == "supported" {
            return hyp["text"];
        }
    }
    return "";
}

def broad_was_rejected(reviewed: list) -> bool {
    for hyp in reviewed {
        if not hyp["narrow"] and hyp["status"] == "contradicted" {
            return True;
        }
    }
    return False;
}

test "skeptic rejects code execution and supports a matching asan frame" {
    excerpt = "ERROR: AddressSanitizer: heap-buffer-overflow READ of size 1";
    reviewed = adjudicate("SANITIZER", "address", "consume_length", excerpt, "");
    assert len(reviewed) == 2;
    assert reviewed[0]["status"] == "supported";
    assert reviewed[1]["status"] == "contradicted";
    assert broad_was_rejected(reviewed);
    assert "consume_length" in narrow_supported_text(reviewed) or "length field" in narrow_supported_text(reviewed);
}

test "normal invariant is not memory corruption" {
    reviewed = adjudicate("NORMAL", "", "", "", "data_before_auth");
    assert reviewed[0]["status"] == "supported";
    assert reviewed[1]["status"] == "contradicted";
    assert "normally" in reviewed[1]["reason"];
}
