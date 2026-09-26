"""Repository evidence ladder.

An observation stays an observation until replay, a location, a narrow
hypothesis, and a rejected broader claim are all present.
"""

def case_status(reproducible: bool, success_count: int, attempt_count: int, minimized: bool,
                narrow_status: str, broad_status: str, has_location: bool) -> str {
    if attempt_count < 3 or success_count * 5 < attempt_count * 4 {
        if success_count > 0 {
            return "ANOMALOUS";
        }
        return "OBSERVED";
    }
    if not reproducible {
        return "ANOMALOUS";
    }
    location_ok = has_location;
    if minimized and narrow_status == "supported" and broad_status == "contradicted" and location_ok {
        return "CONFIRMED_DEFENSIVE_FINDING";
    }
    if narrow_status == "supported" and broad_status == "contradicted" and location_ok {
        return "SUPPORTED_HYPOTHESIS";
    }
    if minimized {
        return "MINIMIZED_FAILURE";
    }
    return "REPRODUCIBLE_FAILURE";
}

def review_case(category: str, file: str, line: int, counter_outcome: str, stdout: str) -> dict {
    broad = {
        "narrow": False,
        "text": "This behavior demonstrates remote code execution.",
        "status": "contradicted",
        "reason": "The record does not show code execution outside the sandboxed process.",
    };
    narrow_text = "A tool reported " + category + ".";
    narrow_status = "unresolved";
    narrow_reason = "No rule matches this category yet.";
    if category == "STATE_INVARIANT_FAILURE" {
        narrow_text = "The COMPLETE state can be entered before verification when action complete follows an unverified order.";
        marker = "complete_before_verification" in stdout or "STATE_INVARIANT_FAILURE" in stdout;
        if counter_outcome == "disappears" and marker {
            narrow_status = "supported";
            narrow_reason = "The marker is present when verification is false and absent when verification is true.";
        } elif counter_outcome == "persists" {
            narrow_status = "contradicted";
            narrow_reason = "The marker still appears when verification is true, so this verification explanation is too specific.";
        } else {
            narrow_reason = "A control input with verification enabled was not compared.";
        }
    } elif category == "JAC_TYPE_ERROR" {
        narrow_text = "The Jac type checker rejected " + file + " at line " + str(line) + ".";
        if file != "" and line > 0 {
            narrow_status = "supported";
            narrow_reason = "jac check failed and the diagnostic names a file and line.";
        } else {
            narrow_reason = "The type checker failed without a source location.";
        }
    } elif category == "JAC_SYNTAX_ERROR" {
        narrow_text = "The file does not parse as Jac.";
        if file != "" {
            narrow_status = "supported";
            narrow_reason = "jac check reported a syntax failure for this file.";
        }
    } elif category == "BROKEN_IMPORT" {
        narrow_text = "An import target named by this file cannot be loaded.";
        if file != "" {
            narrow_status = "supported";
            narrow_reason = "The checker reported a missing module.";
        }
    } elif category == "TEST_FAILURE" {
        narrow_text = "A project test assertion failed when jac test ran this file.";
        if file != "" {
            narrow_status = "supported";
            narrow_reason = "jac test exited non-zero on a test file.";
        }
    } elif category == "UNHANDLED_EXCEPTION" or category == "JAC_RUNTIME_ERROR" {
        narrow_text = "The entrypoint terminates with an exception inside the sandbox.";
        if file != "" {
            narrow_status = "supported";
            narrow_reason = "Replay produced the same abnormal exit.";
        }
    } elif category == "WALKER_FAILURE" {
        narrow_text = "A walker advances completion without the gate it is standing on.";
        if "WALKER_FAILURE" in stdout {
            narrow_status = "supported";
            narrow_reason = "The walker printed WALKER_FAILURE and stayed inside the sandbox.";
        } else {
            narrow_reason = "The walker-failure marker was not in the captured output.";
        }
    } elif category == "MEMORY_SAFETY_FAILURE" or category == "UNDEFINED_BEHAVIOR" {
        narrow_text = "A memory-safety tool reported this execution.";
        narrow_status = "contradicted";
        narrow_reason = "Repository analysis did not capture a sanitizer diagnostic for this record.";
    } elif category == "TIMEOUT" {
        narrow_text = "The command exceeded its wall-clock deadline.";
        narrow_reason = "A timeout can be a slow path rather than a hang.";
    }
    return {
        "narrow": {"narrow": True, "text": narrow_text, "status": narrow_status, "reason": narrow_reason},
        "broad": broad,
    };
}

def claim_for(status: str, category: str, file: str, line: int, narrow_text: str) -> str {
    where = file if file != "" else "an unidentified file";
    if status == "OBSERVED" {
        return "Something unusual was recorded in " + where + ". It has not been reproduced.";
    }
    if status == "ANOMALOUS" {
        return "The behavior in " + where + " appeared on some replays and not others. It is not a stable failure.";
    }
    if status == "CONFIRMED_DEFENSIVE_FINDING" or status == "SUPPORTED_HYPOTHESIS" {
        return narrow_text + " No exploitability claim is made.";
    }
    if status == "MINIMIZED_FAILURE" {
        return "A smaller trigger still produces " + category + " in " + where + ".";
    }
    return "Reproducible " + category + " in " + where + " at line " + str(line) + ".";
}

def title_for(category: str, file: str) -> str {
    if category == "STATE_INVARIANT_FAILURE" {
        return "Completion state reached before verification";
    }
    if category == "TEST_FAILURE" {
        return "Project test failed";
    }
    if category == "JAC_TYPE_ERROR" {
        return "Jac type check failed";
    }
    if category == "JAC_SYNTAX_ERROR" {
        return "Jac syntax check failed";
    }
    if category == "BROKEN_IMPORT" {
        return "Import could not be loaded";
    }
    if category == "UNHANDLED_EXCEPTION" or category == "JAC_RUNTIME_ERROR" {
        return "Entrypoint raised an exception";
    }
    if category == "WALKER_FAILURE" {
        return "Walker advanced without its gate";
    }
    if category == "TIMEOUT" {
        return "Command exceeded its deadline";
    }
    return category + " in " + file;
}

test "observation remains weak without reproduction" {
    status = case_status(False, 1, 1, False, "supported", "contradicted", True);
    assert status == "ANOMALOUS";
    silent = case_status(False, 0, 5, False, "supported", "contradicted", True);
    assert silent == "OBSERVED";
}

test "reproducible failure advances and confirmation needs the full ladder" {
    reproduced = case_status(True, 5, 5, False, "unresolved", "contradicted", True);
    assert reproduced == "REPRODUCIBLE_FAILURE";
    minimized = case_status(True, 5, 5, True, "unresolved", "contradicted", True);
    assert minimized == "MINIMIZED_FAILURE";
    supported = case_status(True, 5, 5, False, "supported", "contradicted", True);
    assert supported == "SUPPORTED_HYPOTHESIS";
    confirmed = case_status(True, 4, 5, True, "supported", "contradicted", True);
    assert confirmed == "CONFIRMED_DEFENSIVE_FINDING";
}

test "unsupported broad hypothesis is rejected and blocks confirmation" {
    reviewed = review_case("STATE_INVARIANT_FAILURE", "checkout/order_graph.jac", 6, "disappears", "STATE_INVARIANT_FAILURE complete_before_verification");
    assert reviewed["broad"]["status"] == "contradicted";
    assert reviewed["narrow"]["status"] == "supported";
    blocked = case_status(True, 5, 5, True, "supported", "unresolved", True);
    assert blocked != "CONFIRMED_DEFENSIVE_FINDING";
    memory = review_case("MEMORY_SAFETY_FAILURE", "a.jac", 1, "not_run", "");
    assert memory["narrow"]["status"] == "contradicted";
    assert "sanitizer" in memory["narrow"]["reason"];
}
