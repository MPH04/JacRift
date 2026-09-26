"""Human-readable report. Every sentence is tied to a stored field."""

import from text { contains_forbidden_claim }

def _lines_for_finding(finding: dict) -> list {
    lines = [];
    lines.append(f"### {finding['finding_id']} — {finding['classification']}");
    lines.append("");
    lines.append(finding["claim"]);
    lines.append("");
    lines.append(f"- Input `{finding['input_id']}` ({finding.get('input_len', 0)} bytes, mutation `{finding.get('mutation', '')}`).");
    lines.append(f"- Exit `{finding.get('exit_type', '')}`, sanitizer `{finding.get('sanitizer', '')}`, frame `{finding.get('frame', '')}`.");
    lines.append(f"- Reproducible: {finding.get('reproducible', False)}. Minimized: {finding.get('minimized', False)}.");
    if finding.get("minimized_len", 0) {
        lines.append(f"- Minimized input `{finding.get('minimized_input_id', '')}` is {finding.get('minimized_len')} bytes (from {finding.get('input_len', 0)}).");
    }
    if finding.get("error_class", "") {
        lines.append(f"- Error class read from the sanitizer text: `{finding['error_class']}`.");
    }
    replay = finding.get("replay_argv", []);
    if replay {
        shown = " ".join(replay);
        lines.append(f"- Replay argv: `{shown}`.");
    }
    lines.append("");
    lines.append("Hypotheses:");
    hyps = finding.get("hypotheses", []);
    if len(hyps) == 0 {
        lines.append("- None generated.");
    }
    for hyp in hyps {
        lines.append(f"- {hyp['status']}: {hyp['text']} ({hyp['reason']})");
    }
    lines.append("");
    return lines;
}

def render_report(state: dict) -> str {
    campaign = state["campaign"];
    metrics = state["metrics"];
    lines = [];
    lines.append("# JacRift report");
    lines.append("");
    lines.append("Synthetic campaign fixture (riftpacket). This report is not a repository-analysis job.");
    lines.append("");
    lines.append(f"Target `{campaign['target_id']}` version `{campaign['target_version']}`.");
    lines.append(f"Compiler `{campaign.get('compiler', '')}`. Coverage mode `{campaign.get('coverage', '')}`.");
    flags = ", ".join(campaign.get("flags", []));
    lines.append(f"Flags: {flags}.");
    lines.append(f"Campaign seed `{campaign.get('seed', '')}`. Status `{campaign.get('status', '')}`.");
    lines.append("");
    lines.append("## Measured");
    lines.append("");
    lines.append(f"- Executions: {metrics.get('executions', 0)}");
    lines.append(f"- Elapsed ms: {metrics.get('elapsed_ms', 0)}");
    lines.append(f"- Executions per second: {metrics.get('execs_per_sec', 0)}");
    lines.append(f"- Corpus entries retained: {metrics.get('corpus_size', 0)}");
    lines.append(f"- Instrumented edges hit: {metrics.get('edges_hit', 0)} of {metrics.get('instrumented_edges', 0)} SanitizerCoverage guards in the target translation unit");
    lines.append(f"- Behavioral keys (Jac recount): {metrics.get('behavior_keys', 0)}");
    lines.append(f"- Engine behavior keys: {metrics.get('behavior_keys_engine', 0)}");
    lines.append(f"- Behavior-counter disagreements: {metrics.get('behavior_disagreements', 0)}");
    lines.append(f"- Sanitizer failures observed: {metrics.get('sanitizer_failures', 0)}");
    lines.append(f"- Crashes without a sanitizer banner: {metrics.get('crashes', 0)}");
    lines.append(f"- Timeouts: {metrics.get('timeouts', 0)}");
    lines.append("");
    lines.append("Edge counts come from the coverage engine. Behavioral keys are recomputed by Jac from the event list. Neither number is a percentage of the source file, and neither is a severity.");
    lines.append("");
    lines.append("## Findings");
    lines.append("");
    findings = state.get("findings", []);
    if len(findings) == 0 {
        lines.append("No finding passed the evidence threshold.");
        lines.append("");
    }
    for finding in findings {
        for line in _lines_for_finding(finding) {
            lines.append(line);
        }
    }
    lines.append("## Experiments");
    lines.append("");
    for exp in state.get("experiments", []) {
        lines.append(f"### {exp['id']}");
        lines.append("");
        lines.append(f"Hypothesis: {exp.get('hypothesis', '')}");
        lines.append(f"Expected: {exp.get('expected', '')}");
        lines.append(f"Observed: {exp.get('observed', '')}");
        lines.append(f"Interpretation: {exp.get('interpretation', '')}");
        lines.append(f"Confidence: {exp.get('confidence', '')}");
        lines.append("");
    }
    lines.append("## What this report does not say");
    lines.append("");
    lines.append("It does not assign a vulnerability-database identifier, a numeric severity score, or an exploitability rating. A sanitizer diagnostic is the diagnostic. A novel state is a novel state.");
    lines.append("");
    lines.append("## Limitations");
    lines.append("");
    for item in state.get("limitations", []) {
        lines.append(f"- {item}");
    }
    lines.append("");
    text = "\n".join(lines);
    banned = contains_forbidden_claim(text);
    if banned != "" {
        text += f"\n\nReport withheld a manufactured claim token `{banned}` by refusing to treat it as a finding title.\n";
    }
    return text;
}

test "report states measurements and refuses severity theater" {
    state = {
        "campaign": {
            "target_id": "riftpacket",
            "target_version": "demo-1",
            "compiler": "clang-18.1",
            "coverage": "trace-pc-guard",
            "flags": ["-fsanitize=address,undefined"],
            "seed": 1,
            "status": "complete",
        },
        "metrics": {
            "executions": 12,
            "elapsed_ms": 100,
            "execs_per_sec": 120.0,
            "corpus_size": 3,
            "edges_hit": 10,
            "instrumented_edges": 66,
            "behavior_keys": 4,
            "behavior_keys_engine": 4,
            "behavior_disagreements": 0,
            "sanitizer_failures": 1,
            "crashes": 0,
            "timeouts": 0,
        },
        "findings": [{
            "finding_id": "f1",
            "classification": "CONFIRMED_SECURITY_FINDING",
            "claim": "Deterministic heap-buffer-overflow reported by the address sanitizer in consume_length. No control-flow hijack was demonstrated.",
            "input_id": "abcdef0123456789",
            "input_len": 5,
            "mutation": "bitflip",
            "exit_type": "SANITIZER",
            "sanitizer": "address",
            "frame": "consume_length",
            "reproducible": True,
            "minimized": True,
            "minimized_len": 5,
            "minimized_input_id": "abcdef0123456789",
            "error_class": "heap-buffer-overflow",
            "replay_argv": ["vrfuzz_riftpacket", "replay", "--input", "min.bin"],
            "hypotheses": [
                {"status": "supported", "text": "length field is trusted", "reason": "frame"},
                {"status": "contradicted", "text": "arbitrary code execution was not shown", "reason": "no pc control"},
            ],
        }],
        "experiments": [],
        "limitations": ["single worker"],
    };
    text = render_report(state);
    assert "12" in text;
    assert "66" in text;
    assert "CVE" not in text;
    assert "CVSS" not in text;
    assert "consume_length" in text;
    assert "No control-flow hijack was demonstrated." in text;
}
