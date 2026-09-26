"""Turn job evidence into an investigation graph, findings, and a report."""

import json;
import os;
import sys;

import from graph { reset_graph }
import from repo_case { case_status, claim_for, review_case, title_for }
import from text { contains_forbidden_claim }

node RepositoryNode {
    has repo_url: str;
    has job_id: str;
}

node AnalysisJobNode {
    has job_id: str;
    has status: str;
}

node ExecutionNode {
    has execution_id: str;
    has tool: str;
}

node EvidenceNode {
    has evidence_id: str;
    has category: str;
    has source: str;
}

node FailureNode {
    has failure_id: str;
    has signature: str;
}

node ReproducerNode {
    has repro_id: str;
    has minimized: bool;
    has command: str;
}

node CaseHypothesis {
    has hyp_id: str;
    has text: str;
    has status: str;
    has narrow: bool;
}

node ExperimentNode {
    has experiment_id: str;
    has result: str;
}

node FindingNode {
    has finding_id: str;
    has status: str;
    has claim: str;
}

node SourceLocationNode {
    has file: str;
    has line: int;
}

edge Produced {}
edge Observed {}
edge Supports {}
edge Contradicts {}
edge Reproduces {}
edge MinimizedTo {}
edge DerivedFrom {}
edge TestsRel {}
edge Affects {}
edge LocatedAt {}

walker SupportWalk {
    has supported: int = 0;
    has contradicted: int = 0;

    can start with Root entry {
        visit [-->];
    }

    can on_finding with FindingNode entry {
        visit [-->];
    }

    can on_hyp with CaseHypothesis entry {
        if here.status == "supported" {
            self.supported += 1;
        } elif here.status == "contradicted" {
            self.contradicted += 1;
        }
    }
}

def read_text(path: str) -> str {
    if not os.path.isfile(path) {
        return "";
    }
    handle = open(path);
    text = handle.read();
    handle.close();
    return text;
}

def write_text(path: str, text: str) {
    handle = open(path, "w");
    handle.write(text);
    handle.close();
}

def as_int(value: any) -> int {
    if type(value) is bool or type(value) is not int {
        return 0;
    }
    return value as int;
}

def load_list(path: str) -> list[dict] {
    text = read_text(path);
    rows: list[dict] = [];
    if text.strip() == "" {
        return rows;
    }
    try {
        data = json.loads(text);
    } except Exception {
        return rows;
    }
    if type(data) is not list {
        return rows;
    }
    for item in data {
        if type(item) is dict {
            rows.append(item as dict);
        }
    }
    return rows;
}

def limitations_for(item: dict, status: str) -> list[str] {
    rows: list[str] = [];
    rows.append("This finding describes behavior inside the sandbox. It is not an exploitability, severity, or CVE assessment.");
    reason = str(item.get("minimize_reason", ""));
    if reason == "diagnostic_command" {
        rows.append("The reproducer is the single tool command. The source file was not rewritten to a smaller program.");
    } elif reason == "json_keys" {
        rows.append("JSON keys that were not required to keep the failure were removed. Byte-level minimization of Jac source was not performed.");
    } elif not item.get("minimized", False) {
        rows.append("No smaller trigger was confirmed.");
    }
    if status == "OBSERVED" or status == "ANOMALOUS" {
        rows.append("Replay did not establish a stable failure.");
    }
    rows.append("What remains unknown: whether this behavior is reachable from any production entrypoint outside the commands JacRift ran.");
    return rows;
}

def render_report(job_id: str, repository: str, findings: list[dict], experiments: list[dict], counts: dict) -> str {
    lines = [];
    lines.append("# JacRift report");
    lines.append("");
    lines.append("Job `" + job_id + "`.");
    lines.append("Repository `" + repository + "`.");
    lines.append("");
    lines.append("## What happened");
    lines.append("");
    if len(findings) == 0 {
        lines.append("No failure passed the evidence gate.");
    } else {
        lines.append(str(len(findings)) + " structured findings were recorded. Each one names a status on the evidence ladder.");
    }
    lines.append("");
    lines.append("Supported hypotheses on the investigation graph: " + str(counts.get("supported", 0)) + ".");
    lines.append("Contradicted hypotheses on the investigation graph: " + str(counts.get("contradicted", 0)) + ".");
    lines.append("");
    for finding in findings {
        lines.append("### " + str(finding.get("finding_id", "")) + " — " + str(finding.get("status", "")));
        lines.append("");
        lines.append(str(finding.get("title", "")));
        lines.append("");
        lines.append(str(finding.get("claim", "")));
        lines.append("");
        lines.append("- Category: `" + str(finding.get("category", "")) + "`.");
        lines.append("- File: `" + str(finding.get("file", "")) + "` line " + str(finding.get("line", 0)) + ".");
        lines.append("- Reproducible: " + str(finding.get("reproducible", False)) + " (" + str(finding.get("reproduction_count", 0)) + "/" + str(finding.get("attempt_count", 0)) + ").");
        lines.append("- Minimized: " + str(finding.get("minimized", False)) + ".");
        hyp = finding.get("hypothesis", {});
        counter = finding.get("counter_evidence", {});
        hyp_status = "";
        hyp_text = "";
        counter_status = "";
        counter_text = "";
        if type(hyp) is dict {
            hyp_status = str(hyp.get("status", ""));
            hyp_text = str(hyp.get("text", ""));
        }
        if type(counter) is dict {
            counter_status = str(counter.get("status", ""));
            counter_text = str(counter.get("text", ""));
        }
        lines.append("- Hypothesis: " + hyp_status + " — " + hyp_text);
        lines.append("- Counter-evidence: " + counter_status + " — " + counter_text);
        lines.append("");
        lines.append("Limitations:");
        notes = finding.get("limitations", []);
        if type(notes) is list {
            for note in (notes as list) {
                lines.append("- " + str(note));
            }
        }
        lines.append("");
    }
    lines.append("## Experiments");
    lines.append("");
    if len(experiments) == 0 {
        lines.append("No bounded experiment was recorded.");
        lines.append("");
    }
    for exp in experiments {
        lines.append("### " + str(exp.get("id", "experiment")));
        lines.append("");
        lines.append("Hypothesis: " + str(exp.get("hypothesis", "")));
        lines.append("Expected: " + str(exp.get("expected", "")));
        lines.append("Observed: " + str(exp.get("observed", "")));
        lines.append("Interpretation: " + str(exp.get("interpretation", "")));
        lines.append("");
    }
    lines.append("## What this report does not say");
    lines.append("");
    lines.append("It does not claim remote code execution, account takeover, a vulnerability score, or a CVE.");
    lines.append("It does not claim the repository was fully explored. Checks were bounded.");
    lines.append("");
    lines.append("## What remains unknown");
    lines.append("");
    lines.append("- Behavior of entrypoints that were skipped because they looked able to spawn shells or open sockets.");
    lines.append("- Build scripts and README commands, which were not executed.");
    lines.append("- Whether a minimized JSON input is minimal at the byte level.");
    lines.append("");
    text = "\n".join(lines);
    banned = contains_forbidden_claim(text);
    if banned != "" {
        text += "\nA forbidden claim token was removed from publication.\n";
    }
    return text;
}

def investigate(directory: str) -> int {
    reset_graph();
    state_path = os.path.join(directory, "state.json");
    state_text = read_text(state_path);
    state: dict = {};
    if state_text.strip() != "" {
        try {
            parsed_state = json.loads(state_text);
            if type(parsed_state) is dict {
                state = parsed_state as dict;
            }
        } except Exception {
            state = {};
        }
    }
    job_id = str(state.get("job_id", ""));
    repository = str(state.get("repository_url", ""));
    evidence = load_list(os.path.join(directory, "evidence.json"));
    experiments = load_list(os.path.join(directory, "experiments.json"));
    repo_node = RepositoryNode(repo_url=repository, job_id=job_id);
    job_node = AnalysisJobNode(job_id=job_id, status="TRIAGING");
    root ++> repo_node;
    root ++> job_node;
    nodes = [];
    edges = [];
    nodes.append({"id": "repository", "type": "Repository", "label": repository, "detail": repository});
    nodes.append({"id": "job", "type": "AnalysisJob", "label": job_id, "detail": job_id});
    edges.append({"source": "repository", "target": "job", "type": "produced"});
    findings = [];
    index = 0;
    for item in evidence {
        index += 1;
        number = str(index);
        if index < 10 {
            number = "000" + number;
        } elif index < 100 {
            number = "00" + number;
        } elif index < 1000 {
            number = "0" + number;
        }
        finding_id = "jr-f-" + number;
        category = str(item.get("category", ""));
        file = str(item.get("file", ""));
        line_no = as_int(item.get("line", 0));
        stdout = str(item.get("stdout", ""));
        reviewed = review_case(category, file, line_no, str(item.get("counter_outcome", "not_run")), stdout);
        narrow = reviewed.get("narrow", {});
        broad = reviewed.get("broad", {});
        narrow_status = "unresolved";
        narrow_text = "";
        broad_status = "contradicted";
        broad_text = "";
        if type(narrow) is dict {
            narrow_status = str(narrow.get("status", "unresolved"));
            narrow_text = str(narrow.get("text", ""));
        }
        if type(broad) is dict {
            broad_status = str(broad.get("status", "contradicted"));
            broad_text = str(broad.get("text", ""));
        }
        status = case_status(
            bool(item.get("reproducible", False)),
            as_int(item.get("success_count", 0)),
            as_int(item.get("attempt_count", 0)),
            bool(item.get("minimized", False)),
            narrow_status,
            broad_status,
            file != "",
        );
        claim = claim_for(status, category, file, line_no, narrow_text);
        if contains_forbidden_claim(claim) != "" {
            claim = "A defensive failure was recorded in " + file + ". The claim text was withheld.";
        }
        command_raw = item.get("command", []);
        shown = "";
        command_list: list[str] = [];
        if type(command_raw) is list {
            for part in (command_raw as list) {
                piece = str(part);
                command_list.append(piece);
                if shown != "" {
                    shown = shown + " ";
                }
                shown = shown + piece;
            }
        }
        finding = {
            "finding_id": finding_id,
            "job_id": job_id,
            "category": category,
            "status": status,
            "title": title_for(category, file),
            "file": file,
            "line": line_no,
            "claim": claim,
            "reproducible": status != "OBSERVED" and status != "ANOMALOUS" and bool(item.get("reproducible", False)),
            "reproduction_count": item.get("success_count", 0),
            "attempt_count": item.get("attempt_count", 0),
            "minimized": bool(item.get("minimized", False)),
            "supporting_evidence": [item.get("evidence_id", "")],
            "contradictory_evidence": [],
            "reproducer": {
                "command": command_list,
                "original": str(item.get("original_input", "")),
                "minimal": str(item.get("minimal_input", "")),
                "reason": str(item.get("minimize_reason", "")),
            },
            "hypothesis": {"narrow": True, "text": narrow_text, "status": narrow_status, "reason": str(narrow.get("reason", "")) if type(narrow) is dict else ""},
            "counter_evidence": {"narrow": False, "text": broad_text, "status": broad_status, "reason": str(broad.get("reason", "")) if type(broad) is dict else ""},
            "limitations": limitations_for(item, status),
            "evidence_id": str(item.get("evidence_id", "")),
            "stdout_excerpt": stdout[0:500],
            "stderr_excerpt": str(item.get("stderr", ""))[0:500],
        };
        if broad_status == "contradicted" {
            finding["contradictory_evidence"].append("broad-hypothesis");
        }
        findings.append(finding);
        exec_id = "exec-" + number;
        ev_id = "evidence-" + number;
        fail_id = "failure-" + number;
        repro_id = "repro-" + number;
        loc_id = "loc-" + number;
        hyp_id = finding_id + "-h";
        broad_id = finding_id + "-broad";
        execution = ExecutionNode(execution_id=exec_id, tool=str(item.get("source", "")));
        evidence_node = EvidenceNode(evidence_id=ev_id, category=category, source=str(item.get("source", "")));
        failure = FailureNode(failure_id=fail_id, signature=str(item.get("signature", "")));
        reproducer = ReproducerNode(repro_id=repro_id, minimized=bool(item.get("minimized", False)), command=shown[0:240]);
        location = SourceLocationNode(file=file, line=line_no);
        finding_node = FindingNode(finding_id=finding_id, status=status, claim=claim[0:240]);
        narrow_node = CaseHypothesis(hyp_id=hyp_id, text=narrow_text, status=narrow_status, narrow=True);
        broad_node = CaseHypothesis(hyp_id=broad_id, text=broad_text, status=broad_status, narrow=False);
        root ++> execution;
        root ++> evidence_node;
        root ++> failure;
        root ++> reproducer;
        root ++> location;
        root ++> finding_node;
        job_node +>: Produced() :+> execution;
        execution +>: Observed() :+> evidence_node;
        evidence_node +>: DerivedFrom() :+> failure;
        failure +>: Reproduces() :+> reproducer;
        reproducer +>: MinimizedTo() :+> finding_node;
        finding_node +>: LocatedAt() :+> location;
        if narrow_status == "contradicted" {
            finding_node +>: Contradicts() :+> narrow_node;
        } else {
            finding_node +>: Supports() :+> narrow_node;
        }
        finding_node +>: Contradicts() :+> broad_node;
        location +>: Affects() :+> failure;
        nodes.append({"id": exec_id, "type": "Execution", "label": str(item.get("source", "")), "detail": shown});
        nodes.append({"id": ev_id, "type": "Evidence", "label": category, "detail": str(item.get("evidence_id", ""))});
        nodes.append({"id": fail_id, "type": "Failure", "label": str(item.get("signature", "")), "detail": category});
        nodes.append({"id": repro_id, "type": "Reproducer", "label": "replay", "detail": shown});
        nodes.append({"id": hyp_id, "type": "Hypothesis", "label": narrow_status, "detail": narrow_text});
        nodes.append({"id": broad_id, "type": "Hypothesis", "label": broad_status, "detail": broad_text});
        nodes.append({"id": finding_id, "type": "Finding", "label": status, "detail": claim});
        nodes.append({"id": loc_id, "type": "SourceLocation", "label": file + ":" + str(line_no), "detail": file + ":" + str(line_no)});
        edges.append({"source": "job", "target": exec_id, "type": "produced"});
        edges.append({"source": exec_id, "target": ev_id, "type": "observed"});
        edges.append({"source": ev_id, "target": fail_id, "type": "derived_from"});
        edges.append({"source": fail_id, "target": repro_id, "type": "reproduces"});
        edges.append({"source": repro_id, "target": finding_id, "type": "minimized_to"});
        edges.append({"source": finding_id, "target": loc_id, "type": "located_at"});
        edges.append({"source": finding_id, "target": hyp_id, "type": "supports" if narrow_status != "contradicted" else "contradicts"});
        edges.append({"source": finding_id, "target": broad_id, "type": "contradicts"});
    }
    exp_index = 0;
    for exp in experiments {
        exp_index += 1;
        exp_id = "experiment-" + str(exp_index);
        observed = str(exp.get("observed", ""));
        experiment = ExperimentNode(experiment_id=exp_id, result=observed);
        root ++> experiment;
        if len(findings) {
            # The control experiment tests the first state-invariant finding when one exists.
            edges.append({"source": exp_id, "target": findings[0]["finding_id"], "type": "tests"});
        }
        nodes.append({"id": exp_id, "type": "Experiment", "label": str(exp.get("id", exp_id)), "detail": str(exp.get("interpretation", ""))});
    }
    auditor = SupportWalk();
    root spawn auditor;
    counts = {"supported": auditor.supported, "contradicted": auditor.contradicted};
    report_body = render_report(job_id, repository, findings, experiments, counts);
    write_text(os.path.join(directory, "findings.json"), json.dumps(findings));
    write_text(os.path.join(directory, "report.md"), report_body);
    write_text(os.path.join(directory, "graph.json"), json.dumps({"nodes": nodes, "edges": edges, "counts": counts}));
    print("findings", len(findings), "supported", counts["supported"], "contradicted", counts["contradicted"]);
    return 0;
}

def run_cli(argv: list) -> int {
    directory = "";
    i = 0;
    while i < len(argv) - 1 {
        if argv[i] == "--job" {
            directory = str(argv[i + 1]);
        }
        i += 1;
    }
    if directory == "" {
        print("missing --job");
        return 2;
    }
    return investigate(directory);
}

with entry:__main__ {
    code = run_cli(sys.argv);
    sys.exit(code);
}
