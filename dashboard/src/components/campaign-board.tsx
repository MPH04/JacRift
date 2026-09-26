"use client";

import { useEffect, useMemo, useState } from "react";

import { campaignBudget, DemoConsole, type DemoStep } from "@/components/demo-console";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { CampaignState, Finding } from "@/lib/types";
import { EMPTY_STATE } from "@/lib/types";

function formatNum(value: number | undefined, digits = 0): string {
  if (value === undefined || Number.isNaN(value)) return "—";
  return value.toLocaleString(undefined, {
    maximumFractionDigits: digits,
    minimumFractionDigits: digits,
  });
}

function classTone(classification: string): string {
  switch (classification) {
    case "CONFIRMED_SECURITY_FINDING":
      return "border-[#9f1239] text-[#9f1239] bg-[#9f1239]/5";
    case "SECURITY_HYPOTHESIS":
      return "border-[#b45309] text-[#9a4d0f] bg-[#b45309]/8";
    case "REPRODUCIBLE_FAILURE":
      return "border-[#7f1d1d] text-[#7f1d1d]";
    case "SUSPICIOUS_DIVERGENCE":
      return "border-[#0f6e6b] text-[#0f6e6b] bg-[#0f6e6b]/8";
    case "NOVEL_BEHAVIOR":
      return "border-[#1c1915] text-[#1c1915]";
    default:
      return "border-[#5c564c] text-[#5c564c]";
  }
}

function SeriesChart({
  series,
  field,
  stroke,
}: {
  series: { execs: number; edges: number; behavior_keys: number }[];
  field: "edges" | "behavior_keys";
  stroke: string;
}) {
  if (series.length < 2) {
    return <p className="text-sm text-[#5c564c]">Waiting for two samples.</p>;
  }
  const width = 320;
  const height = 96;
  const maxX = Math.max(...series.map((point) => point.execs), 1);
  const maxY = Math.max(...series.map((point) => point[field]), 1);
  const path = series
    .map((point, index) => {
      const x = (point.execs / maxX) * (width - 8) + 4;
      const y = height - 8 - (point[field] / maxY) * (height - 16);
      return `${index === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="h-24 w-full" role="img">
      <path d={path} fill="none" stroke={stroke} strokeWidth="2" />
    </svg>
  );
}

export function CampaignBoard() {
  const [state, setState] = useState<CampaignState>(EMPTY_STATE);
  const [loadError, setLoadError] = useState("");
  const [selected, setSelected] = useState("");
  const [busy, setBusy] = useState(false);
  const [starting, setStarting] = useState(false);
  const [detailTab, setDetailTab] = useState("evidence");
  const [replay, setReplay] = useState<string>("");

  async function refresh() {
    try {
      const response = await fetch("/api/state", { cache: "no-store" });
      const body = (await response.json()) as CampaignState;
      setState(body);
      setLoadError("");
    } catch {
      setLoadError("The dashboard could not read campaign state.");
    }
  }

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 1000);
    return () => clearInterval(timer);
  }, []);

  const findings = state.findings ?? [];
  useEffect(() => {
    if (selected && findings.some((finding) => finding.finding_id === selected)) return;
    const preferred =
      findings.find((finding) => finding.classification === "CONFIRMED_SECURITY_FINDING") ?? findings[0];
    setSelected(preferred?.finding_id ?? "");
  }, [findings, selected]);

  const current = useMemo(
    () => findings.find((finding) => finding.finding_id === selected) ?? null,
    [findings, selected],
  );
  const lineage = (state.corpus ?? []).find((row) => row.input_id === current?.input_id)?.lineage ?? [];
  const neighborhood = useMemo(() => {
    if (!current) return [];
    const ids = new Set(
      [current.finding_id, current.input_id, current.minimized_input_id ?? ""].filter((id) => id.length > 0),
    );
    return (state.graph?.edges ?? []).filter(
      (edge) =>
        ids.has(edge.source) ||
        ids.has(edge.target) ||
        edge.source.startsWith(current.finding_id) ||
        edge.target.startsWith(current.finding_id),
    );
  }, [current, state.graph]);
  const status = state.campaign?.status ?? "idle";
  const running = status === "running" || status === "triaging";

  useEffect(() => {
    if (running || status === "complete" || status === "error") setStarting(false);
  }, [running, status]);

  function openSection(id: string, tab?: string) {
    if (tab) setDetailTab(tab);
    document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  async function start(profile: "demo" | "campaign") {
    setBusy(true);
    setStarting(true);
    setReplay("");
    setLoadError("");
    try {
      const payload =
        profile === "demo"
          ? { profile: "demo" }
          : { profile: "campaign", execs: 120, seed: 1, timeout_ms: 250 };
      const response = await fetch("/api/campaign", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      const body = await response.json();
      if (!response.ok) {
        setLoadError(body.error ?? "Campaign did not start.");
        setStarting(false);
      }
    } catch {
      setLoadError("Campaign request failed.");
      setStarting(false);
    } finally {
      setBusy(false);
      void refresh();
    }
  }

  async function reproduce(finding: Finding) {
    setReplay("Replaying…");
    const response = await fetch("/api/reproduce", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ finding_id: finding.finding_id }),
    });
    const body = await response.json();
    if (!response.ok) {
      setReplay(body.error ?? "Replay refused.");
      return;
    }
    const event = body.event;
    setReplay(
      event
        ? `${body.matched ? "Matched" : "Diverged"}: ${event.exit_type} ${event.sanitizer || ""} ${event.frame || ""} in ${event.execution_us} µs`
        : "Replay returned no execution event.",
    );
  }

  const edges = state.metrics?.edges_hit ?? 0;
  const guards = state.metrics?.instrumented_edges ?? 0;
  const findingsReady = findings.length > 0;
  const steps: DemoStep[] = [
    {
      id: "series",
      label: "Coverage and behavior",
      hint: "Two series, counted separately.",
      ready: (state.series?.length ?? 0) >= 2,
      onOpen: () => openSection("series"),
    },
    {
      id: "checks",
      label: "Measured checks",
      hint: "Badges flip from the campaign file.",
      ready: Object.keys(state.checks ?? {}).length > 0,
      onOpen: () => openSection("checks"),
    },
    {
      id: "findings",
      label: "Findings",
      hint: "Classification is the badge.",
      ready: findingsReady,
      onOpen: () => openSection("findings"),
    },
    {
      id: "evidence",
      label: "Evidence",
      hint: "Claim, minimized input, replay.",
      ready: findings.some((finding) => (finding.replay_argv?.length ?? 0) > 0),
      onOpen: () => openSection("investigation", "evidence"),
    },
    {
      id: "hypotheses",
      label: "Hypotheses",
      hint: "Supported and contradicted rows.",
      ready: findings.some((finding) =>
        (finding.hypotheses ?? []).some((item) => item.status === "supported" || item.status === "contradicted"),
      ),
      onOpen: () => openSection("investigation", "hypotheses"),
    },
    {
      id: "lineage",
      label: "Lineage",
      hint: "Corpus ancestry for the input.",
      ready: (state.corpus ?? []).some((row) => (row.lineage?.length ?? 0) > 0),
      onOpen: () => openSection("investigation", "lineage"),
    },
    {
      id: "graph",
      label: "Graph",
      hint: "Edges that touch the finding.",
      ready: (state.graph?.edges?.length ?? 0) > 0,
      onOpen: () => openSection("investigation", "graph"),
    },
    {
      id: "experiments",
      label: "Experiments",
      hint: "Note sweep and scheduled inputs.",
      ready: (state.experiments ?? []).length > 0,
      onOpen: () => openSection("experiments"),
    },
    {
      id: "limitations",
      label: "Limitations",
      hint: "Published with the campaign.",
      ready: (state.limitations ?? []).length > 0,
      onOpen: () => openSection("limitations"),
    },
  ];

  return (
    <main className="mx-auto flex w-full max-w-6xl flex-col gap-6 px-4 py-6 md:px-8">
      <header className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="font-mono text-xs tracking-[0.22em] text-[#5c564c]">LOCAL DEFENSIVE FUZZING</p>
          <h1 className="font-[family-name:var(--font-fraunces)] text-4xl leading-none text-[#1c1915] md:text-5xl">
            Vector<span className="text-[#0f6e6b]">rift</span>
          </h1>
          <p className="mt-2 max-w-xl text-sm text-[#3f3a33]">
            Coverage tells you where the program went. Behavior tells you what it became. Claims stay inside the
            evidence that was actually captured.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="outline">{state.campaign?.target_id ?? "riftpacket"}</Badge>
          <Badge variant="outline">{starting && !running ? "starting" : status}</Badge>
          <Button disabled={busy || running || starting} onClick={() => start("demo")}>
            {running || starting ? "Campaign running" : "Run demo"}
          </Button>
          <Button variant="outline" disabled={busy || running || starting} onClick={() => start("campaign")}>
            120 executions
          </Button>
        </div>
      </header>

      {loadError ? (
        <p className="rounded-md border border-[#9f1239]/40 bg-[#9f1239]/5 px-3 py-2 text-sm text-[#9f1239]">
          {loadError}
        </p>
      ) : null}
      {state.campaign?.error ? (
        <p className="rounded-md border border-[#9f1239]/40 bg-[#9f1239]/5 px-3 py-2 text-sm">{state.campaign.error}</p>
      ) : null}
      {status === "idle" && !starting ? (
        <p className="text-sm text-[#5c564c]">
          No campaign has been published yet. Run demo executes the instrumented riftpacket target on this machine.
          Scope: {state.campaign?.authorized_scope ?? "local synthetic targets in this repository"}.
        </p>
      ) : null}

      <DemoConsole
        status={starting && status === "idle" ? "starting" : status}
        executions={state.metrics?.executions}
        budget={campaignBudget(state.campaign?.id)}
        starting={starting}
        steps={steps}
      />

      <section id="series" className="grid scroll-mt-6 gap-4 md:grid-cols-2">
        <Card className="border-[#e0d3bc] bg-[#faf7f2] shadow-none">
          <CardHeader>
            <CardTitle className="text-sm font-medium tracking-wide text-[#b45309]">Coverage novelty</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="font-mono text-3xl text-[#1c1915]">
              {formatNum(edges)} <span className="text-base text-[#5c564c]">/ {formatNum(guards)} guards</span>
            </p>
            <SeriesChart series={state.series ?? []} field="edges" stroke="#b45309" />
            <p className="text-xs text-[#5c564c]">Instrumented edges hit in the target translation unit.</p>
          </CardContent>
        </Card>
        <Card className="border-[#d5e4e2] bg-[#f7fbfa] shadow-none">
          <CardHeader>
            <CardTitle className="text-sm font-medium tracking-wide text-[#0f6e6b]">Behavior novelty</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="font-mono text-3xl text-[#1c1915]">{formatNum(state.metrics?.behavior_keys)}</p>
            <SeriesChart series={state.series ?? []} field="behavior_keys" stroke="#0f6e6b" />
            <p className="text-xs text-[#5c564c]">
              Jac recount of behavioral keys. Engine reported {formatNum(state.metrics?.behavior_keys_engine)}.
              Disagreements: {formatNum(state.metrics?.behavior_disagreements)}.
            </p>
          </CardContent>
        </Card>
      </section>

      <section className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {[
          ["Executions", formatNum(state.metrics?.executions)],
          ["Per second", formatNum(state.metrics?.execs_per_sec, 1)],
          ["Corpus", formatNum(state.metrics?.corpus_size)],
          ["Sanitizer hits", formatNum(state.metrics?.sanitizer_failures)],
          ["Workers", status === "running" ? "1" : "0"],
        ].map(([label, value]) => (
          <div key={label} className="rounded-lg border border-[#e4dccf] bg-[#faf7f2] px-3 py-2">
            <p className="text-xs text-[#5c564c]">{label}</p>
            <p className="font-mono text-xl">{value}</p>
          </div>
        ))}
      </section>

      <section id="checks" className="flex scroll-mt-6 flex-wrap gap-2 text-xs">
        {Object.entries(state.checks ?? {}).map(([name, ok]) => (
          <Badge key={name} variant="outline" className={ok ? "border-[#0f6e6b] text-[#0f6e6b]" : ""}>
            {name.replaceAll("_", " ")}: {ok ? "measured" : "not shown"}
          </Badge>
        ))}
      </section>

      <Separator />

      <div id="findings" className="grid scroll-mt-6 gap-4 lg:grid-cols-[280px_1fr]">
        <Card className="shadow-none">
          <CardHeader>
            <CardTitle className="text-base">Findings</CardTitle>
          </CardHeader>
          <CardContent>
            {findings.length === 0 ? (
              <p className="text-sm text-[#5c564c]">None yet. A running campaign fills this list from Jac.</p>
            ) : (
              <ScrollArea className="h-[420px] pr-3">
                <ul className="flex flex-col gap-2">
                  {findings.map((finding) => (
                    <li key={finding.finding_id}>
                      <button
                        type="button"
                        onClick={() => {
                          setSelected(finding.finding_id);
                          setReplay("");
                        }}
                        className={`w-full rounded-md border px-2 py-2 text-left ${
                          selected === finding.finding_id ? "border-[#1c1915] bg-white" : "border-transparent"
                        }`}
                      >
                        <Badge variant="outline" className={classTone(finding.classification)}>
                          {finding.classification.replaceAll("_", " ")}
                        </Badge>
                        <p className="mt-1 font-mono text-[11px] text-[#5c564c]">{finding.signature}</p>
                      </button>
                    </li>
                  ))}
                </ul>
              </ScrollArea>
            )}
          </CardContent>
        </Card>

        <Card id="investigation" className="scroll-mt-6 shadow-none">
          <CardHeader>
            <CardTitle className="text-base">Investigation</CardTitle>
          </CardHeader>
          <CardContent>
            {!current ? (
              <p className="text-sm text-[#5c564c]">Select a finding.</p>
            ) : (
              <Tabs value={detailTab} onValueChange={(value) => setDetailTab(String(value))}>
                <TabsList>
                  <TabsTrigger value="evidence">Evidence</TabsTrigger>
                  <TabsTrigger value="hypotheses">Hypotheses</TabsTrigger>
                  <TabsTrigger value="lineage">Lineage</TabsTrigger>
                  <TabsTrigger value="graph">Graph</TabsTrigger>
                </TabsList>
                <TabsContent value="evidence" className="mt-3 space-y-3">
                  <p className="text-sm leading-6">{current.claim}</p>
                  <dl className="grid grid-cols-2 gap-2 text-sm">
                    <div>
                      <dt className="text-xs text-[#5c564c]">Exit</dt>
                      <dd className="font-mono">{current.exit_type || "—"}</dd>
                    </div>
                    <div>
                      <dt className="text-xs text-[#5c564c]">Frame</dt>
                      <dd className="font-mono">{current.frame || "—"}</dd>
                    </div>
                    <div>
                      <dt className="text-xs text-[#5c564c]">Reproduced</dt>
                      <dd>{current.reproducible ? "yes" : "no"}</dd>
                    </div>
                    <div>
                      <dt className="text-xs text-[#5c564c]">Minimized</dt>
                      <dd>
                        {current.minimized
                          ? `${current.input_len} → ${current.minimized_len} bytes`
                          : "no"}
                      </dd>
                    </div>
                  </dl>
                  {current.minimized_hex ? (
                    <pre className="overflow-x-auto rounded-md bg-[#1c1915] p-3 font-mono text-xs text-[#f4f0e7]">
                      {current.minimized_hex}
                    </pre>
                  ) : null}
                  <Button variant="outline" onClick={() => reproduce(current)} disabled={!current.replay_argv?.length}>
                    Replay stored input
                  </Button>
                  {replay ? <p className="font-mono text-xs">{replay}</p> : null}
                  {current.replay_argv?.length ? (
                    <p className="break-all font-mono text-[11px] text-[#5c564c]">{current.replay_argv.join(" ")}</p>
                  ) : null}
                </TabsContent>
                <TabsContent value="hypotheses" className="mt-3 space-y-2">
                  {(current.hypotheses ?? []).length === 0 ? (
                    <p className="text-sm text-[#5c564c]">No hypothesis was generated for this record.</p>
                  ) : (
                    (current.hypotheses ?? []).map((hyp) => (
                      <div key={hyp.text} className="rounded-md border border-[#e4dccf] p-2">
                        <Badge variant="outline">{hyp.status}</Badge>
                        <p className="mt-1 text-sm">{hyp.text}</p>
                        <p className="text-xs text-[#5c564c]">{hyp.reason}</p>
                      </div>
                    ))
                  )}
                </TabsContent>
                <TabsContent value="graph" className="mt-3 space-y-2">
                  <p className="text-xs text-[#5c564c]">
                    Investigation graph holds {formatNum(state.graph?.nodes?.length)} nodes and{" "}
                    {formatNum(state.graph?.edges?.length)} edges. Shown here: edges that touch this finding or its
                    input.
                  </p>
                  {neighborhood.length === 0 ? (
                    <p className="text-sm text-[#5c564c]">No graph edges reference this finding.</p>
                  ) : (
                    <ul className="space-y-1 font-mono text-[11px]">
                      {neighborhood.map((edge) => (
                        <li key={`${edge.type}-${edge.source}-${edge.target}`}>
                          {edge.source} — {edge.type} → {edge.target}
                        </li>
                      ))}
                    </ul>
                  )}
                </TabsContent>
                <TabsContent value="lineage" className="mt-3">
                  {lineage.length === 0 ? (
                    <p className="text-sm text-[#5c564c]">
                      No corpus lineage for this input. Experiment inputs are created directly.
                    </p>
                  ) : (
                    <ol className="flex flex-col gap-2">
                      {lineage.map((step) => (
                        <li key={step.input_id} className="font-mono text-xs">
                          {step.mutation} · {step.input_id}
                        </li>
                      ))}
                    </ol>
                  )}
                </TabsContent>
              </Tabs>
            )}
          </CardContent>
        </Card>
      </div>

      <div id="experiments" className="grid scroll-mt-6 gap-4 md:grid-cols-2">
        <Card className="shadow-none">
          <CardHeader>
            <CardTitle className="text-base">Experiments</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {(state.experiments ?? []).length === 0 ? (
              <p className="text-sm text-[#5c564c]">None recorded.</p>
            ) : (
              (state.experiments ?? []).map((experiment) => (
                <div key={experiment.id}>
                  <p className="font-mono text-xs text-[#0f6e6b]">{experiment.id}</p>
                  <p className="text-sm">{experiment.interpretation}</p>
                  <p className="text-xs text-[#5c564c]">Observed: {experiment.observed}</p>
                </div>
              ))
            )}
          </CardContent>
        </Card>
        <Card className="shadow-none">
          <CardHeader>
            <CardTitle className="text-base">Agent decisions</CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-48">
              <ul className="space-y-2 text-sm">
                {(state.agents ?? []).map((agent, index) => (
                  <li key={`${agent.agent}-${index}`}>
                    <span className="font-mono text-xs text-[#5c564c]">{agent.agent}</span> {agent.action}. {agent.detail}
                  </li>
                ))}
              </ul>
            </ScrollArea>
          </CardContent>
        </Card>
      </div>

      <footer id="limitations" className="scroll-mt-6 space-y-2 pb-8 text-xs text-[#5c564c]">
        <p>
          Compiler {state.campaign?.compiler || "—"} · seed {state.campaign?.seed ?? "—"} · generated{" "}
          {state.generated_at || "—"} · timeouts {formatNum(state.metrics?.timeouts)} · crashes{" "}
          {formatNum(state.metrics?.crashes)}
        </p>
        <ul className="list-disc space-y-1 pl-4">
          {(state.limitations ?? []).map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </footer>
    </main>
  );
}
