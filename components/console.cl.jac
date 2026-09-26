"""JacRift repository analysis console."""

import from react { useEffect }

def:pub Metric(label: str, value: str) -> JsxElement {
    return
        <div style={{"background": "#fffdf8", "border": "1px solid #d9d1c3", "borderRadius": "10px", "padding": "0.55rem 0.7rem"}}>
            <div style={{"fontSize": "0.75rem", "color": "#5c564c"}}>{label}</div>
            <div style={{"fontSize": "1.2rem"}}>{value}</div>
        </div>;
}

def:pub Tab(label: str, active: bool, onClick: Callable[[MouseEvent], None]) -> JsxElement {
    weight = "600" if active else "400";
    return <button type="button" onClick={onClick} style={{"border": "none", "borderBottom": ("2px solid #0f6e6b" if active else "2px solid transparent"), "background": "transparent", "padding": "0.35rem 0.2rem", "fontWeight": weight}}>{label}</button>;
}

def:pub FindingButton(finding_id: str, title: str, status: str, active: bool, onPick: Callable[[str], None]) -> JsxElement {
    def handle(e: MouseEvent) { onPick(finding_id); }
    background = "#e7f4f2" if active else "white";
    return
        <button type="button" onClick={handle} style={{"display": "block", "width": "100%", "textAlign": "left", "marginBottom": "0.4rem", "padding": "0.55rem", "borderRadius": "8px", "border": "1px solid #d9d1c3", "background": background}}>
            <strong>{title}</strong>
            <div style={{"fontSize": "0.78rem", "color": "#5c564c"}}>{status}</div>
        </button>;
}

def:pub NodeButton(node_id: str, kind: str, label: str, active: bool, onPick: Callable[[str], None]) -> JsxElement {
    def handle(e: MouseEvent) { onPick(node_id); }
    background = "#e7f4f2" if active else "white";
    return
        <button type="button" onClick={handle} style={{"border": "1px solid #d9d1c3", "borderRadius": "8px", "background": background, "padding": "0.45rem 0.6rem"}}>
            <div style={{"fontSize": "0.72rem", "color": "#5c564c"}}>{kind}</div>
            {label}
        </button>;
}

def unwrap(payload: any) -> any {
    if not payload {
        return {};
    }
    data = payload;
    if payload["data"] {
        inner = payload["data"];
        if inner["result"] {
            data = inner["result"];
        }
    }
    return data;
}

def:pub Console -> JsxElement {
    has repository_url: str = "fixture://safe-buggy",
        authorized: bool = False,
        job_id: str = "",
        error_text: str = "",
        busy: bool = False,
        raw: any = None,
        selected: str = "",
        node_id: str = "",
        replay_text: str = "",
        panel: str = "findings";

    useEffect(lambda {
        interval = setInterval(lambda { poll(); }, 1500);
        return lambda { clearInterval(interval); };
    }, [job_id]);

    async def poll {
        if job_id == "" {
            return;
        }
        response = await fetch("/api/jobs/" + job_id, {"method": "GET"});
        payload = await response.json();
        raw = unwrap(payload);
    }

    async def on_submit(e: FormEvent) {
        e.preventDefault();
        if not authorized {
            error_text = "Confirm that you own this repository or have authorization to test it.";
            return;
        }
        busy = True;
        error_text = "";
        replay_text = "";
        response = await fetch("/api/jobs", {
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body": JSON.stringify({
                "repository_url": repository_url,
                "authorization_confirmed": True,
                "scope": "repository_only",
            }),
        });
        payload = await response.json();
        body = unwrap(payload);
        busy = False;
        if body["ok"] {
            job_id = str(body["job_id"]);
            selected = "";
            node_id = "";
        } else {
            error_text = str(body["error"] or "The repository was rejected.");
        }
    }

    async def on_replay {
        if job_id == "" or selected == "" {
            return;
        }
        replay_text = "Replaying…";
        response = await fetch("/api/jobs/" + job_id + "/reproduce", {
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body": JSON.stringify({"finding_id": selected, "job_id": job_id}),
        });
        payload = await response.json();
        body = unwrap(payload);
            if body["ok"] {
            replay_text = "Replay matched " + str(body["matched"]) + " attempts.";
        } else {
            replay_text = str(body["error"] or "Replay failed.");
        }
    }

    async def on_delete {
        if job_id == "" {
            return;
        }
        response = await fetch("/api/jobs/" + job_id, {"method": "DELETE"});
        payload = await response.json();
        body = unwrap(payload);
        if body["deleted"] {
            job_id = "";
            raw = None;
            selected = "";
        } else {
            error_text = "Cancellation requested. The job stops between phases.";
            poll();
        }
    }

    def on_url(e: ChangeEvent) { repository_url = e.target.value; }
    def on_auth(e: ChangeEvent) { authorized = e.target.checked; }
    def show_findings(e: MouseEvent) { panel = "findings"; }
    def show_graph(e: MouseEvent) { panel = "graph"; }
    def show_log(e: MouseEvent) { panel = "log"; }
    def show_report(e: MouseEvent) { panel = "report"; }
    def pick_finding(finding_id: str) { selected = finding_id; replay_text = ""; }
    def pick_node(picked_id: str) { node_id = picked_id; }

    status = "idle";
    phase = "";
    repo = repository_url;
    metrics = {};
    stages = [];
    findings = [];
    graph = {};
    log_text = "";
    report_text = "";
    job_error = "";
    if raw {
        status = str(raw["status"] or "idle");
        phase = str(raw["phase"] or "");
        repo = str(raw["repository_url"] or repository_url);
        metrics = raw["metrics"] or {};
        stages = raw["stages"] or [];
        findings = raw["findings"] or [];
        graph = raw["graph"] or {};
        log_text = str(raw["log"] or "");
        report_text = str(raw["report"] or "");
        job_error = str(raw["job_error"] or "");
    }
    current = None;
    for item in findings {
        if item["finding_id"] == selected {
            current = item;
        }
    }
    nodes = graph["nodes"] or [];
    edges = graph["edges"] or [];
    picked = None;
    for item in nodes {
        if item["id"] == node_id {
            picked = item;
        }
    }

    return
        <main style={{"maxWidth": "1080px", "margin": "0 auto", "padding": "1.5rem 1rem 3rem"}}>
            <header style={{"marginBottom": "1.25rem"}}>
                <p style={{"letterSpacing": "0.18em", "fontSize": "0.75rem", "color": "#5c564c", "margin": "0"}}>DEFENSIVE REPOSITORY ANALYSIS</p>
                <h1 style={{"fontFamily": "Georgia, serif", "fontWeight": "500", "fontSize": "2.6rem", "margin": "0.2rem 0"}}>
                    Jac<span style={{"color": "#0f6e6b"}}>Rift</span>
                </h1>
                <p style={{"maxWidth": "40rem", "lineHeight": "1.45"}}>
                    Submit an authorized Jac repository. JacRift observes it in a disposable sandbox,
                    replays failures, and shows the evidence behind each finding.
                </p>
            </header>
            <form onSubmit={on_submit} style={{"background": "#fffdf8", "border": "1px solid #d9d1c3", "borderRadius": "12px", "padding": "1rem"}}>
                <label style={{"display": "block", "fontSize": "0.85rem", "marginBottom": "0.35rem"}}>Repository</label>
                <input
                    value={repository_url}
                    onChange={on_url}
                    placeholder="https://github.com/OWNER/REPOSITORY"
                    style={{"width": "100%", "boxSizing": "border-box", "padding": "0.65rem 0.75rem", "border": "1px solid #cfc6b8", "borderRadius": "8px"}}
                />
                <label style={{"display": "flex", "gap": "0.5rem", "alignItems": "flex-start", "margin": "0.8rem 0"}}>
                    <input type="checkbox" checked={authorized} onChange={on_auth} />
                    <span>I confirm that I own this repository or have authorization to test it.</span>
                </label>
                <button
                    type="submit"
                    disabled={busy}
                    style={{"background": "#0f6e6b", "color": "white", "border": "none", "borderRadius": "8px", "padding": "0.6rem 1rem", "cursor": "pointer"}}
                >
                    {("Working…" if busy else "Analyze Repository")}
                </button>
                <p style={{"color": "#7f1d1d", "minHeight": "1.2rem"}}>{error_text}</p>
                <p style={{"color": "#5c564c", "fontSize": "0.85rem", "margin": "0"}}>
                    The built-in demonstration fixture is <code>fixture://safe-buggy</code>. It is labeled TEST / DEMONSTRATION FIXTURES.
                </p>
            </form>
            {if job_id != "" {
                <section style={{"marginTop": "1.25rem"}}>
                    <div style={{"display": "flex", "justifyContent": "space-between", "gap": "1rem", "alignItems": "center"}}>
                        <div>
                            <h2 style={{"margin": "0"}}>{job_id}</h2>
                            <p style={{"margin": "0.2rem 0", "color": "#5c564c"}}>{repo} · {status} · {phase}</p>
                        </div>
                        <button type="button" onClick={on_delete} style={{"border": "1px solid #cfc6b8", "background": "white", "borderRadius": "8px", "padding": "0.4rem 0.7rem"}}>Cancel / delete</button>
                    </div>
                    {if job_error != "" { <p style={{"color": "#7f1d1d"}}>{job_error}</p> }}
                    <ol style={{"display": "flex", "flexWrap": "wrap", "gap": "0.4rem", "padding": "0", "listStyle": "none"}}>
                        {[
                            <li key={stage["name"]} style={{
                                "border": "1px solid #d9d1c3",
                                "borderRadius": "999px",
                                "padding": "0.2rem 0.6rem",
                                "fontSize": "0.8rem",
                                "background": ("#d7efe9" if stage["state"] == "done" else ("#fff4d6" if stage["state"] == "current" else "white"))
                            }}>{stage["name"]}</li>
                            for stage in stages
                        ]}
                    </ol>
                    <div style={{"display": "grid", "gridTemplateColumns": "repeat(auto-fit, minmax(120px, 1fr))", "gap": "0.5rem"}}>
                        <Metric label="Jac files" value={str(metrics["jac_files"] or 0)} />
                        <Metric label="Tests" value={str(metrics["tests_discovered"] or 0)} />
                        <Metric label="Checks" value={str(metrics["checks_executed"] or 0)} />
                        <Metric label="Runtime" value={str(metrics["runtime_executions"] or 0)} />
                        <Metric label="Observations" value={str(metrics["observations"] or 0)} />
                        <Metric label="Reproduced" value={str(metrics["reproduced_failures"] or 0)} />
                        <Metric label="Findings" value={str(metrics["findings"] or 0)} />
                    </div>
                    <div style={{"display": "flex", "gap": "0.4rem", "margin": "0.8rem 0"}}>
                        <Tab label="Findings" active={panel == "findings"} onClick={show_findings} />
                        <Tab label="Graph" active={panel == "graph"} onClick={show_graph} />
                        <Tab label="Logs" active={panel == "log"} onClick={show_log} />
                        <Tab label="Report" active={panel == "report"} onClick={show_report} />
                    </div>
                    {if panel == "findings" {
                        <div style={{"display": "grid", "gridTemplateColumns": "minmax(220px, 280px) 1fr", "gap": "0.8rem"}}>
                            <div>
                                {[
                                    <FindingButton
                                        key={item["finding_id"]}
                                        finding_id={item["finding_id"]}
                                        title={item["title"]}
                                        status={item["status"]}
                                        active={item["finding_id"] == selected}
                                        onPick={pick_finding}
                                    />
                                    for item in findings
                                ]}
                                {if len(findings) == 0 { <p>No findings yet.</p> }}
                            </div>
                            {if current {
                                <article style={{"background": "#fffdf8", "border": "1px solid #d9d1c3", "borderRadius": "12px", "padding": "0.9rem"}}>
                                    <p style={{"margin": "0", "color": "#0f6e6b", "fontSize": "0.8rem"}}>{current["category"]}</p>
                                    <h3 style={{"margin": "0.2rem 0"}}>{current["title"]}</h3>
                                    <p><strong>Status.</strong> {current["status"]}</p>
                                    <p><strong>Where.</strong> {current["file"]}:{str(current["line"])}</p>
                                    <p>{current["claim"]}</p>
                                    <p><strong>Hypothesis.</strong> {current["hypothesis_status"]} — {current["hypothesis"]}</p>
                                    <p><strong>Counter-evidence.</strong> {current["counter_status"]} — {current["counter_evidence"]}</p>
                                    <p><strong>Replay.</strong> {str(current["reproduction_count"])} / {str(current["attempt_count"])}. Minimized: {str(current["minimized"])}.</p>
                                    <p><strong>Minimal reproducer.</strong></p>
                                    <pre style={{"whiteSpace": "pre-wrap", "background": "#f6f1e7", "padding": "0.6rem", "borderRadius": "8px"}}>{JSON.stringify(current["reproducer"] or {})}</pre>
                                    <p><strong>Limitations.</strong></p>
                                    <ul>
                                        {[<li key={str(idx)}>{str(note)}</li> for (idx, note) in enumerate(current["limitations"] or [])]}
                                    </ul>
                                    <button type="button" onClick={on_replay} style={{"border": "1px solid #0f6e6b", "background": "white", "borderRadius": "8px", "padding": "0.4rem 0.7rem"}}>Replay finding</button>
                                    <p>{replay_text}</p>
                                    <details>
                                        <summary>Raw evidence excerpts</summary>
                                        <pre style={{"whiteSpace": "pre-wrap"}}>{str(current["stdout_excerpt"] or "")}</pre>
                                        <pre style={{"whiteSpace": "pre-wrap"}}>{str(current["stderr_excerpt"] or "")}</pre>
                                    </details>
                                </article>
                            } else {
                                <p>Select a finding to read the claim, the replay, and what is still unknown.</p>
                            }}
                        </div>
                    }}
                    {if panel == "graph" {
                        <div>
                            <p>Each node is a step in the reasoning: execution, evidence, failure, reproducer, hypothesis, experiment, finding.</p>
                            <div style={{"display": "flex", "flexWrap": "wrap", "gap": "0.4rem"}}>
                                {[
                                    <NodeButton
                                        key={item["id"]}
                                        node_id={item["id"]}
                                        kind={item["type"]}
                                        label={item["label"]}
                                        active={item["id"] == node_id}
                                        onPick={pick_node}
                                    />
                                    for item in nodes
                                ]}
                            </div>
                            {if picked {
                                <pre style={{"whiteSpace": "pre-wrap", "background": "#fffdf8", "padding": "0.7rem", "borderRadius": "8px"}}>{picked["type"] + " " + picked["id"] + " — " + str(picked["detail"] or picked["label"])}</pre>
                            }}
                            <ul>
                                {[<li key={edge["source"] + edge["type"] + edge["target"]}>{edge["source"] + " —" + edge["type"] + "→ " + edge["target"]}</li> for edge in edges]}
                            </ul>
                        </div>
                    }}
                    {if panel == "log" {
                        <pre style={{"whiteSpace": "pre-wrap", "background": "#1c1915", "color": "#f3efe4", "padding": "0.8rem", "borderRadius": "8px", "maxHeight": "28rem", "overflow": "auto"}}>{log_text or "No log lines yet."}</pre>
                    }}
                    {if panel == "report" {
                        <pre style={{"whiteSpace": "pre-wrap", "background": "#fffdf8", "border": "1px solid #d9d1c3", "padding": "0.8rem", "borderRadius": "8px"}}>{report_text or "The report is written when investigation finishes."}</pre>
                    }}
                </section>
            }}
        </main>;
}
