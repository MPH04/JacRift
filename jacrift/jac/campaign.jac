"""Campaign orchestration. Jac owns ingest, triage, experiments, and the report."""

import datetime;
import fcntl;
import json;
import os;
import shutil;
import subprocess;
import sys;
import time;

import from classify { classify_evidence }
import from corpus { fresh_corpus, retention_reason }
import from experiments {
    divergence_probe,
    note_probe,
    overflow_scale,
    plan_experiments,
    stretch_length,
}
import from graph {
    Contradicts,
    DecisionNode,
    ExecNode,
    ExecutedOn,
    Finding,
    GeneratedBy,
    HypothesisNode,
    InputNode,
    MinimizedTo,
    MutatedFrom,
    Supports,
    TargetNode,
    Triggered,
    ancestry_of,
    cluster_ids,
    evidence_counts,
    reset_graph,
}
import from hypotheses { adjudicate, broad_was_rejected, narrow_supported_text }
import from novelty { first_invariant, fresh_book }
import from report { render_report }
import from schema { parse_execution }
import from text { contains_forbidden_claim, is_hex_id, sanitize_token }

def repo_root() -> str {
    here = os.path.dirname(os.path.abspath(__file__));
    return os.path.dirname(here);
}

def now_iso() -> str {
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ");
}

def json_safe(value: any) -> any {
    if value is None or type(value) is str or type(value) is bool or type(value) is int or type(value) is float {
        return value;
    }
    if type(value) is dict {
        out = {};
        for key in value {
            if str(key) == "_node" or str(key) == "events" {
                continue;
            }
            out[str(key)] = json_safe(value[key]);
        }
        return out;
    }
    if type(value) is list {
        out = [];
        for item in value {
            out.append(json_safe(item));
        }
        return out;
    }
    return str(value);
}

def write_json(path: str, payload: dict) {
    parent = os.path.dirname(path);
    if parent != "" {
        os.makedirs(parent, exist_ok=True);
    }
    tmp = path + ".tmp";
    fh = open(tmp, "w");
    fh.write(json.dumps(json_safe(payload)));
    fh.close();
    os.replace(tmp, path);
}

def read_json(path: str) -> dict {
    if not os.path.isfile(path) {
        return {};
    }
    fh = open(path);
    text = fh.read();
    fh.close();
    try {
        data = json.loads(text);
    } except Exception {
        return {};
    }
    if type(data) is not dict {
        return {};
    }
    return data;
}

def write_bytes(path: str, data: bytes) {
    parent = os.path.dirname(path);
    if parent != "" {
        os.makedirs(parent, exist_ok=True);
    }
    fh = open(path, "wb");
    fh.write(data);
    fh.close();
}

def limitations() -> list {
    return [
        "One worker. Campaigns do not run concurrent target executions.",
        "Coverage counts are SanitizerCoverage guards in the instrumented target translation unit, not a fraction of source lines.",
        "AddressSanitizer reserves a large virtual address space, so RLIMIT_AS is not applied. CPU time, file size, core dumps, wall-clock timeout, and output truncation are applied.",
        "Behavioral keys are recomputed by Jac from sanitized events. The engine's behavior_new counter is kept beside that recount.",
        "Confirmed findings state only the sanitizer-observed bug class. They do not claim control of the instruction pointer.",
        "libFuzzer is a separate binary used as a second engine check. The campaign loop is vrfuzz, which supplies the callbacks.",
        "No remote model is consulted. Agents are deterministic Jac walkers and rules.",
    ];
}

def empty_state(base: str) -> dict {
    return {
        "schema": "vectorrift.state.v1",
        "generated_at": now_iso(),
        "campaign": {
            "id": "",
            "target_id": "riftpacket",
            "target_version": "demo-1",
            "status": "idle",
            "error": "",
            "seed": 1,
            "compiler": "",
            "coverage": "trace-pc-guard",
            "sanitizers": ["address", "undefined"],
            "flags": [],
            "binary": "",
            "authorized_scope": "local synthetic targets owned by this repository",
        },
        "metrics": {
            "executions": 0,
            "elapsed_ms": 0,
            "execs_per_sec": 0,
            "corpus_size": 0,
            "instrumented_edges": 0,
            "edges_hit": 0,
            "behavior_keys": 0,
            "behavior_keys_engine": 0,
            "behavior_disagreements": 0,
            "sanitizer_failures": 0,
            "crashes": 0,
            "timeouts": 0,
            "novel_behavior": 0,
        },
        "series": [],
        "findings": [],
        "agents": [],
        "graph": {"nodes": [], "edges": []},
        "corpus": [],
        "experiments": [],
        "limitations": limitations(),
        "checks": {
            "coverage_guided": False,
            "behavior_independent": False,
            "agents_acted": False,
            "reproduced": False,
            "jac_graph": False,
        },
        "paths": {"root": base, "state": os.path.join(base, "var", "state.json")},
    };
}

def add_agent(state: dict, agent: str, action: str, detail: str) {
    state["agents"].append({
        "agent": agent,
        "action": action,
        "detail": detail if len(detail) <= 240 else detail[0:240],
    });
}

def run_argv(argv: list, timeout_s: int) -> dict {
    try {
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout_s, check=False);
    } except Exception as exc {
        return {"code": 9, "stdout": "", "stderr": str(exc)};
    }
    return {"code": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr};
}

def parse_stdout_event(stdout: str) -> dict {
    line = "";
    for candidate in stdout.splitlines() {
        if "\"schema\"" in candidate {
            line = candidate;
        }
    }
    if line == "" {
        return {"ok": False, "error": "no_event", "event": {}};
    }
    return parse_execution(line);
}

def replay_input(binary: str, path: str, timeout_ms: int) -> dict {
    result = run_argv([binary, "replay", "--input", path, "--timeout-ms", str(timeout_ms)], 30);
    parsed = parse_stdout_event(result["stdout"]);
    parsed["runner_code"] = result["code"];
    if not parsed["ok"] {
        parsed["error_detail"] = result["stderr"][-400:];
    }
    return parsed;
}

def compare_inputs(binary: str, before: str, path: str, timeout_ms: int) -> dict {
    result = run_argv(
        [binary, "compare", "--before", before, "--input", path, "--timeout-ms", str(timeout_ms)],
        30,
    );
    return parse_stdout_event(result["stdout"]);
}

def signatures_match(original: dict, replayed: dict) -> bool {
    if original["exit_type"] != replayed["exit_type"] {
        return False;
    }
    if original["sanitizer"] != replayed["sanitizer"] {
        return False;
    }
    if original["frame"] != "" and replayed["frame"] != "" and original["frame"] != replayed["frame"] {
        return False;
    }
    return True;
}

def artifact_path(fuzz_out: str, event: dict) -> str {
    name = event["input_id"] + ".bin";
    failure = os.path.join(fuzz_out, "failures", name);
    if os.path.isfile(failure) {
        return failure;
    }
    corpus = os.path.join(fuzz_out, "corpus", name);
    if os.path.isfile(corpus) {
        return corpus;
    }
    return "";
}

def remember_input(state: dict, nodes: dict, event: dict) -> InputNode {
    input_id = event["input_id"];
    if input_id in nodes {
        return nodes[input_id];
    }
    created = InputNode(
        input_id=input_id,
        parent_id=event["parent_id"],
        mutation=event["mutation"],
        input_len=event["input_len"],
        input_hex=event["input_hex"],
    );
    root ++> created;
    nodes[input_id] = created;
    state["graph"]["nodes"].append({
        "id": input_id,
        "type": "Input",
        "label": event["mutation"] + " " + str(event["input_len"]) + "b",
    });
    parent_id = event["parent_id"];
    if parent_id != "" and parent_id in nodes {
        created +>: MutatedFrom() :+> nodes[parent_id];
        state["graph"]["edges"].append({
            "source": input_id,
            "target": parent_id,
            "type": "MUTATED_FROM",
        });
    }
    return created;
}

def attach_hypotheses(state: dict, finding_node: Finding, finding: dict) {
    index = 0;
    hyps = finding["hypotheses"];
    for item in hyps {
        index += 1;
        prefix = finding["finding_id"];
        hyp_id = prefix + "-h" + str(index);
        created_hyp = HypothesisNode(
            hyp_id=hyp_id,
            text=item["text"],
            status=item["status"],
            reason=item["reason"],
            narrow=item["narrow"],
        );
        if item["status"] == "contradicted" {
            finding_node +>: Contradicts() :+> created_hyp;
            edge_type = "CONTRADICTS";
        } else {
            finding_node +>: Supports() :+> created_hyp;
            edge_type = "SUPPORTS";
        }
        state["graph"]["nodes"].append({
            "id": hyp_id,
            "type": "Hypothesis",
            "label": item["status"],
        });
        state["graph"]["edges"].append({
            "source": finding["finding_id"],
            "target": hyp_id,
            "type": edge_type,
        });
    }
}

def classify_failure(event: dict, reproducible: bool, replay_matches: bool, minimized: bool) -> dict {
    invariant = first_invariant(event["events"]);
    reviewed = adjudicate(event["exit_type"], event["sanitizer"], event["frame"], event["stderr_excerpt"], invariant);
    verdict = classify_evidence(
        event["exit_type"],
        event["sanitizer"],
        event["frame"],
        event["stderr_excerpt"],
        invariant,
        event["behavior_new"],
        reproducible,
        replay_matches,
        minimized,
        narrow_supported_text(reviewed) != "",
        broad_was_rejected(reviewed),
        narrow_supported_text(reviewed),
    );
    verdict["hypotheses"] = reviewed;
    verdict["invariant"] = invariant;
    return verdict;
}

def load_events(path: str) -> dict {
    if not os.path.isfile(path) {
        return {"events": [], "rejected": 0};
    }
    fh = open(path);
    text = fh.read();
    fh.close();
    events = [];
    rejected = 0;
    for line in text.splitlines() {
        if line.strip() == "" {
            continue;
        }
        parsed = parse_execution(line);
        if not parsed["ok"] {
            rejected += 1;
            continue;
        }
        events.append(parsed["event"]);
    }
    return {"events": events, "rejected": rejected};
}

def ingest(state: dict, events: list, fuzz_out: str) -> dict {
    book = fresh_book();
    corpus = fresh_corpus();
    nodes = {};
    series = [];
    disagreements = 0;
    sanitizers = 0;
    crashes = 0;
    timeouts = 0;
    guided = False;
    failure_seen = {};
    invariant_seen = {};
    novel_seen = {};
    findings = [];
    step = 1;
    if len(events) > 90 {
        step = len(events) // 90;
    }
    index = 0;
    for event in events {
        observed = book.observe(event["events"]);
        if observed["new_count"] != event["behavior_new"] {
            disagreements += 1;
        }
        if event["exit_type"] == "SANITIZER" {
            sanitizers += 1;
        } elif event["exit_type"] == "CRASH" {
            crashes += 1;
        } elif event["exit_type"] == "TIMEOUT" {
            timeouts += 1;
        }
        if event["mutation"] != "seed" and event["new_edges"] > 0 {
            guided = True;
        }
        reason = retention_reason(event["new_edges"], observed["new_count"], event["exit_type"]);
        if reason != "" {
            corpus.add(event["input_id"], event["parent_id"], event["mutation"], event["input_len"], reason);
        }
        created = remember_input(state, nodes, event);
        executed = ExecNode(
            exec_index=event["exec_index"],
            exit_type=event["exit_type"],
            sanitizer=event["sanitizer"],
            frame=event["frame"],
            new_edges=event["new_edges"],
            behavior_new=observed["new_count"],
            fingerprint=observed["fingerprint"],
        );
        root ++> executed;
        created +>: ExecutedOn() :+> executed;
        exec_id = "e" + str(event["exec_index"]);
        state["graph"]["nodes"].append({
            "id": exec_id,
            "type": "Execution",
            "label": event["exit_type"],
        });
        state["graph"]["edges"].append({
            "source": event["input_id"],
            "target": exec_id,
            "type": "EXECUTED_ON",
        });
        if index % step == 0 or index == len(events) - 1 {
            series.append({
                "execs": event["exec_index"] + 1,
                "edges": event["edges_seen_total"],
                "behavior_keys": len(book.counts),
            });
        }
        invariant = first_invariant(event["events"]);
        make = False;
        signature = "";
        if event["exit_type"] == "SANITIZER" or event["exit_type"] == "CRASH" or event["exit_type"] == "TIMEOUT" {
            signature = event["exit_type"] + "|" + event["sanitizer"] + "|" + event["frame"];
            if signature not in failure_seen {
                failure_seen[signature] = True;
                make = True;
            }
        } elif invariant != "" and invariant not in invariant_seen {
            invariant_seen[invariant] = True;
            signature = "invariant|" + invariant;
            make = True;
        } elif observed["new_count"] > 0 and len(novel_seen) < 6 {
            key = observed["new_keys"][0];
            if key not in novel_seen and (key.startswith("semantic:") or key.startswith("transition:")) {
                novel_seen[key] = True;
                signature = "behavior|" + key;
                make = True;
            }
        }
        if make {
            finding_id = "f-" + event["input_id"];
            path = artifact_path(fuzz_out, event);
            finding = {
                "finding_id": finding_id,
                "classification": "CAPTURED",
                "claim": "",
                "signature": signature,
                "input_id": event["input_id"],
                "parent_id": event["parent_id"],
                "mutation": event["mutation"],
                "input_len": event["input_len"],
                "input_hex": event["input_hex"],
                "exit_type": event["exit_type"],
                "sanitizer": event["sanitizer"],
                "frame": event["frame"],
                "stderr_excerpt": event["stderr_excerpt"],
                "behavior_new": observed["new_count"],
                "new_edges": event["new_edges"],
                "fingerprint": observed["fingerprint"],
                "events": event["events"],
                "artifact": path,
                "reproducible": False,
                "replay_matches": False,
                "minimized": False,
                "minimized_len": 0,
                "minimized_input_id": "",
                "minimized_hex": "",
                "error_class": "",
                "hypotheses": [],
                "replay_argv": [],
                "cluster_id": signature,
            };
            findings.append(finding);
            fnode = Finding(
                finding_id=finding_id,
                classification="CAPTURED",
                claim="",
                signature=signature,
                input_id=event["input_id"],
                reproducible=False,
                minimized=False,
            );
            root ++> fnode;
            executed +>: Triggered() :+> fnode;
            state["graph"]["nodes"].append({
                "id": finding_id,
                "type": "Finding",
                "label": "CAPTURED",
            });
            state["graph"]["edges"].append({
                "source": exec_id,
                "target": finding_id,
                "type": "TRIGGERED",
            });
            finding["_node"] = fnode;
        }
        index += 1;
    }
    last_edges = 0;
    if len(events) {
        last_edges = events[-1]["edges_seen_total"];
    }
    guards = 0;
    if len(events) {
        guards = events[-1]["guards"];
    }
    return {
        "findings": findings,
        "series": series,
        "corpus": corpus,
        "nodes": nodes,
        "disagreements": disagreements,
        "sanitizers": sanitizers,
        "crashes": crashes,
        "timeouts": timeouts,
        "guided": guided,
        "edges": last_edges,
        "guards": guards,
        "behavior_keys": len(book.counts),
        "book": book,
        "notes": note_count(book),
    };
}

def note_count(book: object) -> int {
    total = 0;
    for key in book.counts {
        if key.startswith("semantic:note:") {
            total += 1;
        }
    }
    return total;
}

def seen_flags(findings: list) -> dict {
    address = False;
    undefined = False;
    invariant = False;
    unreproduced = 0;
    unminimized = 0;
    for finding in findings {
        if finding["sanitizer"] == "address" {
            address = True;
        }
        if finding["sanitizer"] == "undefined" {
            undefined = True;
        }
        if finding["signature"].startswith("invariant|") {
            invariant = True;
        }
        abnormal = finding["exit_type"] == "SANITIZER" or finding["exit_type"] == "CRASH";
        if abnormal and not finding["reproducible"] {
            unreproduced += 1;
        }
        if abnormal and finding["reproducible"] and not finding["minimized"] {
            unminimized += 1;
        }
    }
    return {
        "address": address,
        "undefined": undefined,
        "invariant": invariant,
        "unreproduced": unreproduced,
        "unminimized": unminimized,
    };
}

def apply_verdict(state: dict, finding: dict, verdict: dict) {
    finding["classification"] = verdict["classification"];
    finding["claim"] = verdict["claim"];
    finding["error_class"] = verdict["error_class"];
    finding["hypotheses"] = verdict["hypotheses"];
    finding["reproducible"] = verdict["reproducible"];
    finding["_node"].classification = verdict["classification"];
    finding["_node"].claim = verdict["claim"];
    finding["_node"].reproducible = verdict["reproducible"];
    finding["_node"].minimized = finding["minimized"];
    graph_nodes = state["graph"]["nodes"];
    for item in graph_nodes {
        if item["id"] == finding["finding_id"] {
            item["label"] = verdict["classification"];
        }
    }
    attach_hypotheses(state, finding["_node"], finding);
    for hyp in verdict["hypotheses"] {
        add_agent(state, "skeptic", hyp["status"], hyp["reason"]);
    }
}

def classify_benign(state: dict, findings: list) {
    for finding in findings {
        if finding["classification"] != "CAPTURED" {
            continue;
        }
        if finding["exit_type"] == "SANITIZER" or finding["exit_type"] == "CRASH" or finding["exit_type"] == "TIMEOUT" {
            continue;
        }
        verdict = classify_failure(finding, False, False, False);
        apply_verdict(state, finding, verdict);
    }
}

def reproduce_and_minimize(state: dict, binary: str, fuzz_out: str, work: str, timeout_ms: int, findings: list) {
    for finding in findings {
        if finding["classification"] != "CAPTURED" {
            continue;
        }
        if finding["exit_type"] != "SANITIZER" and finding["exit_type"] != "CRASH" and finding["exit_type"] != "TIMEOUT" {
            continue;
        }
        path = finding["artifact"];
        if path == "" or not os.path.isfile(path) {
            add_agent(state, "reproduction", "skipped", "no saved artifact for " + finding["finding_id"]);
            continue;
        }
        replay_argv = [binary, "replay", "--input", path, "--timeout-ms", str(timeout_ms)];
        finding["replay_argv"] = replay_argv;
        parsed = replay_input(binary, path, timeout_ms);
        if not parsed["ok"] {
            add_agent(state, "reproduction", "failed", parsed.get("error", "replay failed"));
            verdict = classify_failure(finding, False, False, False);
            apply_verdict(state, finding, verdict);
            continue;
        }
        replayed = parsed["event"];
        matches = signatures_match(finding, replayed);
        finding["replay_matches"] = matches;
        finding["frame"] = replayed["frame"] if replayed["frame"] != "" else finding["frame"];
        finding["stderr_excerpt"] = replayed["stderr_excerpt"];
        add_agent(
            state,
            "reproduction",
            "matched" if matches else "diverged",
            finding["input_id"] + " -> " + replayed["exit_type"] + " " + replayed["frame"],
        );
        minimized = False;
        if matches and finding["exit_type"] != "TIMEOUT" {
            min_dir = os.path.join(work, "minimized");
            os.makedirs(min_dir, exist_ok=True);
            min_path = os.path.join(min_dir, finding["input_id"] + ".bin");
            result = run_argv(
                [binary, "minimize", "--input", path, "--out", min_path, "--timeout-ms", str(timeout_ms)],
                60,
            );
            min_event = parse_stdout_event(result["stdout"]);
            if min_event["ok"] or "\"ok\":true" in result["stdout"] or "\"ok\": true" in result["stdout"] {
                try {
                    summary = json.loads(result["stdout"].strip().splitlines()[-1]);
                } except Exception {
                    summary = {};
                }
                if summary.get("ok") and os.path.isfile(min_path) {
                    check = replay_input(binary, min_path, timeout_ms);
                    if check["ok"] and signatures_match(replayed, check["event"]) {
                        minimized = True;
                        finding["minimized"] = True;
                        finding["minimized_len"] = summary.get("minimized_len", 0);
                        finding["minimized_input_id"] = summary.get("input_id", "");
                        raw = open(min_path, "rb").read();
                        finding["minimized_hex"] = raw.hex();
                        finding["stderr_excerpt"] = check["event"]["stderr_excerpt"];
                        finding["frame"] = check["event"]["frame"];
                        finding["replay_argv"] = [binary, "replay", "--input", min_path, "--timeout-ms", str(timeout_ms)];
                        add_agent(
                            state,
                            "minimization",
                            "preserved",
                            str(summary.get("original_len", finding["input_len"])) + " -> " + str(finding["minimized_len"]),
                        );
                        if finding["minimized_input_id"] != "" {
                            mini = InputNode(
                                input_id=finding["minimized_input_id"],
                                parent_id=finding["input_id"],
                                mutation="minimize",
                                input_len=finding["minimized_len"],
                                input_hex=finding["minimized_hex"][0:192],
                            );
                            root ++> mini;
                            state["graph"]["nodes"].append({
                                "id": finding["minimized_input_id"],
                                "type": "Input",
                                "label": "minimized",
                            });
                            state["graph"]["edges"].append({
                                "source": finding["input_id"],
                                "target": finding["minimized_input_id"],
                                "type": "MINIMIZED_TO",
                            });
                        }
                    } else {
                        add_agent(state, "minimization", "rejected", "minimized input did not preserve the signature");
                    }
                }
            }
        }
        verdict = classify_failure(finding, True, matches, minimized);
        apply_verdict(state, finding, verdict);
    }
}

def record_experiment(state: dict, exp_id: str, hypothesis: str, expected: str, observed: str, interpretation: str, confidence: str) {
    state["experiments"].append({
        "id": exp_id,
        "hypothesis": hypothesis,
        "expected": expected,
        "observed": observed,
        "interpretation": interpretation,
        "confidence": confidence,
        "next": "",
    });
    add_agent(state, "next-experiment", exp_id, interpretation);
}

def stage_captured(state: dict, fuzz_out: str, event: dict, payload: bytes, mutation: str, findings: list) -> bool {
    signature = event["exit_type"] + "|" + event["sanitizer"] + "|" + event["frame"];
    for existing in findings {
        if existing["signature"] == signature {
            return False;
        }
    }
    extra = os.path.join(fuzz_out, "failures");
    os.makedirs(extra, exist_ok=True);
    dest = os.path.join(extra, event["input_id"] + ".bin");
    write_bytes(dest, payload);
    fid = "f-" + event["input_id"];
    fnode = Finding(
        finding_id=fid,
        classification="CAPTURED",
        claim="",
        signature=signature,
        input_id=event["input_id"],
        reproducible=False,
        minimized=False,
    );
    root ++> fnode;
    findings.append({
        "finding_id": fid,
        "classification": "CAPTURED",
        "claim": "",
        "signature": signature,
        "input_id": event["input_id"],
        "parent_id": "",
        "mutation": mutation,
        "input_len": len(payload),
        "input_hex": payload.hex(),
        "exit_type": event["exit_type"],
        "sanitizer": event["sanitizer"],
        "frame": event["frame"],
        "stderr_excerpt": event["stderr_excerpt"],
        "behavior_new": event["behavior_new"],
        "new_edges": event["new_edges"],
        "fingerprint": event["fingerprint"],
        "events": event["events"],
        "artifact": dest,
        "reproducible": False,
        "replay_matches": False,
        "minimized": False,
        "minimized_len": 0,
        "minimized_input_id": "",
        "minimized_hex": "",
        "error_class": "",
        "hypotheses": [],
        "replay_argv": [],
        "cluster_id": signature,
        "_node": fnode,
    });
    state["graph"]["nodes"].append({"id": fid, "type": "Finding", "label": "CAPTURED"});
    return True;
}

def run_directional(state: dict, binary: str, work: str, timeout_ms: int, book: object, findings: list, fuzz_out: str, notes_seen: int) {
    flags = seen_flags(findings);
    plan = plan_experiments(
        flags["address"], flags["undefined"], flags["invariant"], notes_seen, 0, 0
    );
    independent = False;
    for item in plan {
        if item["id"] == "note_sweep" {
            exp_dir = os.path.join(work, "experiments");
            os.makedirs(exp_dir, exist_ok=True);
            before = os.path.join(exp_dir, "note_before.bin");
            write_bytes(before, note_probe(0));
            flat = 0;
            changed = 0;
            for index in range(1, 8) {
                path = os.path.join(exp_dir, "note_" + str(index) + ".bin");
                write_bytes(path, note_probe(index));
                parsed = compare_inputs(binary, before, path, timeout_ms);
                if not parsed["ok"] {
                    continue;
                }
                event = parsed["event"];
                observed = book.observe(event["events"]);
                if event["new_edges"] == 0 {
                    flat += 1;
                }
                if observed["new_count"] > 0 or event["behavior_new"] > 0 {
                    changed += 1;
                }
                if event["new_edges"] == 0 and event["behavior_new"] > 0 {
                    independent = True;
                }
            }
            record_experiment(
                state,
                "note_sweep",
                "A one-byte semantic label can be new behavior without a new instrumented edge.",
                "compare() reports new_edges == 0 and behavior_new > 0 for a sibling note.",
                f"{flat} siblings had no new edges; {changed} carried a new engine behavior key.",
                "Behavior novelty is not implied by an edge-count increase." if independent else "This run did not separate behavior from coverage.",
                "high" if independent else "low",
            );
        } elif item["id"] == "length_past_end" {
            exp_dir = os.path.join(work, "experiments");
            os.makedirs(exp_dir, exist_ok=True);
            seed_path = os.path.join(repo_root(), "corpus", "seeds", "riftpacket", "04_length.bin");
            raw = b"";
            if os.path.isfile(seed_path) {
                fh = open(seed_path, "rb");
                raw = fh.read();
                fh.close();
            }
            stretched = stretch_length(raw);
            observed = "seed missing or too short";
            if len(stretched) > 0 {
                path = os.path.join(exp_dir, "length_past_end.bin");
                write_bytes(path, stretched);
                parsed = replay_input(binary, path, timeout_ms);
                if parsed["ok"] {
                    event = parsed["event"];
                    observed = event["exit_type"] + " " + event["sanitizer"] + " " + event["frame"];
                    if event["exit_type"] == "SANITIZER" {
                        event["mutation"] = "length_past_end";
                        event["parent_id"] = "";
                        event["saved"] = True;
                        extra = os.path.join(fuzz_out, "failures");
                        os.makedirs(extra, exist_ok=True);
                        dest = os.path.join(extra, event["input_id"] + ".bin");
                        write_bytes(dest, stretched);
                        event["artifact_hint"] = dest;
                        findings.append({
                            "finding_id": "f-" + event["input_id"],
                            "classification": "CAPTURED",
                            "claim": "",
                            "signature": event["exit_type"] + "|" + event["sanitizer"] + "|" + event["frame"],
                            "input_id": event["input_id"],
                            "parent_id": "",
                            "mutation": "length_past_end",
                            "input_len": len(stretched),
                            "input_hex": stretched.hex(),
                            "exit_type": event["exit_type"],
                            "sanitizer": event["sanitizer"],
                            "frame": event["frame"],
                            "stderr_excerpt": event["stderr_excerpt"],
                            "behavior_new": event["behavior_new"],
                            "new_edges": event["new_edges"],
                            "fingerprint": event["fingerprint"],
                            "events": event["events"],
                            "artifact": dest,
                            "reproducible": False,
                            "replay_matches": False,
                            "minimized": False,
                            "minimized_len": 0,
                            "minimized_input_id": "",
                            "minimized_hex": "",
                            "error_class": "",
                            "hypotheses": [],
                            "replay_argv": [],
                            "cluster_id": "",
                            "_node": Finding(
                                finding_id="f-" + event["input_id"],
                                classification="CAPTURED",
                                claim="",
                                signature=event["exit_type"] + "|" + event["sanitizer"] + "|" + event["frame"],
                                input_id=event["input_id"],
                                reproducible=False,
                                minimized=False,
                            ),
                        });
                        root ++> findings[-1]["_node"];
                    }
                } else {
                    observed = "replay failed";
                }
            }
            record_experiment(
                state,
                "length_past_end",
                "Setting the trusted length above the remaining bytes reads off the object.",
                "AddressSanitizer reports an overflow in consume_length.",
                observed,
                "The experiment produced the sanitizer report the mutation budget had not." if "SANITIZER" in observed else "No new address-sanitizer report from this crafted input.",
                "high" if "address" in observed else "medium",
            );
        } elif item["id"] == "scale_overflow" {
            exp_dir = os.path.join(work, "experiments");
            path = os.path.join(exp_dir, "scale.bin");
            write_bytes(path, overflow_scale());
            parsed = replay_input(binary, path, timeout_ms);
            observed = "replay failed";
            if parsed["ok"] {
                event = parsed["event"];
                observed = event["exit_type"] + " " + event["sanitizer"] + " " + event["frame"];
                if event["exit_type"] == "SANITIZER" {
                    stage_captured(state, fuzz_out, event, overflow_scale(), "scale_overflow", findings);
                }
            }
            record_experiment(
                state,
                "scale_overflow",
                "Two large int32 factors overflow in apply_scale.",
                "UndefinedBehaviorSanitizer reports a signed overflow.",
                observed,
                "Signed overflow is a sanitizer fact, not an exploitability claim.",
                "high" if "undefined" in observed else "low",
            );
        } elif item["id"] == "data_before_auth" {
            exp_dir = os.path.join(work, "experiments");
            path = os.path.join(exp_dir, "divergence.bin");
            write_bytes(path, divergence_probe());
            parsed = replay_input(binary, path, timeout_ms);
            observed = "replay failed";
            if parsed["ok"] {
                event = parsed["event"];
                invariant = first_invariant(event["events"]);
                observed = event["exit_type"] + " invariant=" + invariant;
            }
            record_experiment(
                state,
                "data_before_auth",
                "A data opcode before authentication violates the state machine without a memory error.",
                "Normal exit and invariant data_before_auth.",
                observed,
                "This is a suspicious divergence, not a sanitizer finding.",
                "high" if "data_before_auth" in observed else "low",
            );
        }
    }
    return independent;
}

def publish(state: dict, report_path: str) {
    public = [];
    for finding in state["findings"] {
        copied = {};
        for key in finding {
            if key != "_node" and key != "events" {
                copied[key] = finding[key];
            }
        }
        public.append(copied);
    }
    state["findings"] = public;
    text = render_report(state);
    parent = os.path.dirname(report_path);
    if parent != "" {
        os.makedirs(parent, exist_ok=True);
    }
    fh = open(report_path, "w");
    fh.write(text);
    fh.close();
    write_json(state["paths"]["state"], state);
}

def run_campaign(execs: int, seed: int, timeout_ms: int) -> dict {
    repo = repo_root();
    state = empty_state(repo);
    work = os.path.join(repo, "var", "campaign");
    state_path = state["paths"]["state"];
    os.makedirs(work, exist_ok=True);
    lock_path = os.path.join(repo, "var", "campaign.lock");
    lock_fh = open(lock_path, "w");
    try {
        fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB);
    } except Exception {
        lock_fh.close();
        state["campaign"]["status"] = "error";
        state["campaign"]["error"] = "Another campaign holds var/campaign.lock.";
        write_json(state_path, state);
        return state;
    }
    try {
        binary = os.path.join(repo, "native", "build", "vrfuzz_riftpacket");
        seeds = os.path.join(repo, "corpus", "seeds", "riftpacket");
        fuzz_out = os.path.join(work, "fuzz");
        state["campaign"]["binary"] = binary;
        state["campaign"]["seed"] = seed;
        state["campaign"]["id"] = "riftpacket-" + str(seed) + "-" + str(execs);
        if not os.path.isfile(binary) {
            state["campaign"]["status"] = "error";
            state["campaign"]["error"] = "Missing " + binary + ". Run scripts/build.sh.";
            publish(state, os.path.join(repo, "var", "report.md"));
            return state;
        }
        if os.path.isdir(fuzz_out) {
            shutil.rmtree(fuzz_out);
        }
        reset_graph();
        target = TargetNode(target_id="riftpacket", version="demo-1");
        root ++> target;
        state["graph"]["nodes"].append({"id": "riftpacket", "type": "Target", "label": "riftpacket demo-1"});
        state["campaign"]["status"] = "running";
        publish(state, os.path.join(repo, "var", "report.md"));
        proc = subprocess.Popen(
            [binary, "run", "--seeds", seeds, "--out", fuzz_out, "--seed", str(seed), "--execs", str(execs), "--timeout-ms", str(timeout_ms)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        );
        deadline = time.time() + 180;
        while proc.poll() is None {
            progress = read_json(os.path.join(fuzz_out, "progress.json"));
            if progress {
                state["metrics"]["executions"] = progress.get("executions", 0);
                state["metrics"]["elapsed_ms"] = progress.get("elapsed_ms", 0);
                state["metrics"]["execs_per_sec"] = progress.get("execs_per_sec", 0);
                state["metrics"]["edges_hit"] = progress.get("edges_seen", 0);
                state["metrics"]["instrumented_edges"] = progress.get("guards", 0);
                state["metrics"]["behavior_keys_engine"] = progress.get("behavior_keys", 0);
                state["metrics"]["corpus_size"] = progress.get("corpus_size", 0);
                state["metrics"]["sanitizer_failures"] = progress.get("sanitizer_failures", 0);
                state["metrics"]["timeouts"] = progress.get("timeouts", 0);
                state["generated_at"] = now_iso();
                write_json(state_path, state);
            }
            if time.time() > deadline {
                proc.kill();
                break;
            }
            time.sleep(0.3);
        }
        (stdout, stderr) = proc.communicate(timeout=20);
        summary = read_json(os.path.join(fuzz_out, "summary.json"));
        if proc.returncode not in [0, None] or not summary {
            state["campaign"]["status"] = "error";
            state["campaign"]["error"] = (stderr or stdout or "fuzzer failed")[-500:];
            publish(state, os.path.join(repo, "var", "report.md"));
            return state;
        }
        state["campaign"]["compiler"] = summary.get("compiler", "");
        state["campaign"]["flags"] = summary.get("flags", []);
        state["campaign"]["target_version"] = summary.get("target_version", "demo-1");
        loaded = load_events(os.path.join(fuzz_out, "events.jsonl"));
        if loaded["rejected"] {
            state["limitations"].append(str(loaded["rejected"]) + " event lines were rejected by the schema.");
        }
        packed = ingest(state, loaded["events"], fuzz_out);
        state["findings"] = packed["findings"];
        state["series"] = packed["series"];
        state["metrics"]["executions"] = summary.get("executions", len(loaded["events"]));
        state["metrics"]["elapsed_ms"] = summary.get("elapsed_ms", 0);
        state["metrics"]["execs_per_sec"] = summary.get("execs_per_sec", 0);
        state["metrics"]["corpus_size"] = summary.get("corpus_size", 0);
        state["metrics"]["instrumented_edges"] = packed["guards"];
        state["metrics"]["edges_hit"] = packed["edges"];
        state["metrics"]["behavior_keys"] = packed["behavior_keys"];
        state["metrics"]["behavior_keys_engine"] = summary.get("behavior_keys", 0);
        state["metrics"]["behavior_disagreements"] = packed["disagreements"];
        state["metrics"]["sanitizer_failures"] = packed["sanitizers"];
        state["metrics"]["crashes"] = packed["crashes"];
        state["metrics"]["timeouts"] = packed["timeouts"];
        state["metrics"]["novel_behavior"] = packed["behavior_keys"];
        state["campaign"]["status"] = "triaging";
        write_json(state_path, state);
        classify_benign(state, state["findings"]);
        reproduce_and_minimize(state, binary, fuzz_out, work, timeout_ms, state["findings"]);
        independent = run_directional(
            state, binary, work, timeout_ms, packed["book"], state["findings"], fuzz_out, packed["notes"]
        );
        # Failures created by an experiment still need reproduction.
        reproduce_and_minimize(state, binary, fuzz_out, work, timeout_ms, state["findings"]);
        groups = cluster_ids();
        add_agent(state, "cluster", "grouped", str(len(groups)) + " signatures");
        counts = evidence_counts();
        add_agent(
            state,
            "evidence",
            "counted",
            str(counts["supported"]) + " supported, " + str(counts["contradicted"]) + " contradicted",
        );
        corpus_rows = [];
        guided = packed["guided"];
        for input_id in packed["corpus"].items {
            row = packed["corpus"].items[input_id];
            lineage = packed["corpus"].lineage(input_id);
            corpus_rows.append({
                "input_id": input_id,
                "parent_id": row["parent_id"],
                "mutation": row["mutation"],
                "input_len": row["input_len"],
                "reason": row["reason"],
                "lineage": lineage,
            });
            if row["mutation"] != "seed" and "new_edges" in row["reason"] {
                guided = True;
            }
        }
        state["corpus"] = corpus_rows;
        if len(corpus_rows) {
            sample = corpus_rows[-1];
            if sample["input_id"] in packed["nodes"] and sample["parent_id"] != "" {
                walked = ancestry_of(packed["nodes"][sample["input_id"]]);
                add_agent(state, "ancestry", "walked", " -> ".join(walked)[0:180]);
            }
        }
        reproduced = False;
        for finding in state["findings"] {
            if finding.get("reproducible") {
                reproduced = True;
            }
        }
        state["checks"] = {
            "coverage_guided": guided and state["metrics"]["edges_hit"] > 0,
            "behavior_independent": independent,
            "agents_acted": len(state["agents"]) > 0,
            "reproduced": reproduced,
            "jac_graph": len(groups) > 0 or len(state["findings"]) == 0,
        };
        state["campaign"]["status"] = "complete";
        state["generated_at"] = now_iso();
        banned = contains_forbidden_claim(json.dumps(json_safe(state["findings"])));
        if banned != "" {
            state["campaign"]["status"] = "error";
            state["campaign"]["error"] = "Refusing to publish a finding that contains " + banned;
        }
        publish(state, os.path.join(repo, "var", "report.md"));
        return state;
    } except Exception as exc {
        state["campaign"]["status"] = "error";
        state["campaign"]["error"] = str(exc);
        try {
            publish(state, os.path.join(repo, "var", "report.md"));
        } except Exception {
            write_json(state_path, state);
        }
        return state;
    } finally {
        lock_fh.close();
    }
}

def run_cli(argv: list) -> int {
    execs = 400;
    seed = 1;
    timeout_ms = 250;
    i = 0;
    while i < len(argv) - 1 {
        if argv[i] == "--execs" {
            execs = int(argv[i + 1]);
        } elif argv[i] == "--seed" {
            seed = int(argv[i + 1]);
        } elif argv[i] == "--timeout-ms" {
            timeout_ms = int(argv[i + 1]);
        }
        i += 1;
    }
    if execs < 1 {
        execs = 1;
    }
    if execs > 20000 {
        execs = 20000;
    }
    state = run_campaign(execs, seed, timeout_ms);
    print(state["campaign"]["status"], state["campaign"].get("error", ""));
    print(
        "execs", state["metrics"]["executions"],
        "edges", state["metrics"]["edges_hit"], "/", state["metrics"]["instrumented_edges"],
        "behavior", state["metrics"]["behavior_keys"],
        "findings", len(state["findings"]),
    );
    if state["campaign"]["status"] == "error" {
        return 2;
    }
    return 0;
}

test "directional length input is a sanitizer event when the binary exists" {
    binary = os.path.join(repo_root(), "native", "build", "vrfuzz_riftpacket");
    if os.path.isfile(binary) {
        work = os.path.join(repo_root(), "var", "unit-length");
        os.makedirs(work, exist_ok=True);
        path = os.path.join(work, "stretched.bin");
        raw = open(os.path.join(repo_root(), "corpus", "seeds", "riftpacket", "04_length.bin"), "rb").read();
        stretched = stretch_length(raw);
        write_bytes(path, stretched);
        parsed = replay_input(binary, path, 500);
        assert parsed["ok"];
        assert parsed["event"]["exit_type"] == "SANITIZER";
        assert parsed["event"]["sanitizer"] == "address";
        assert "consume_length" in parsed["event"]["frame"];
    }
}
