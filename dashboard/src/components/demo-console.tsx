"use client";

import { useEffect, useState } from "react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export type DemoStep = {
  id: string;
  label: string;
  hint: string;
  ready: boolean;
  onOpen: () => void;
};

export function campaignBudget(id: string | undefined): number | null {
  if (!id) return null;
  const match = /^riftpacket-(\d+)-(\d+)$/.exec(id);
  if (!match) return null;
  const value = Number(match[2]);
  return Number.isInteger(value) && value > 0 ? value : null;
}

export function DemoConsole({
  status,
  executions,
  budget,
  starting,
  steps,
}: {
  status: string;
  executions?: number;
  budget: number | null;
  starting: boolean;
  steps: DemoStep[];
}) {
  const [log, setLog] = useState("");
  const [report, setReport] = useState("");
  const [ready, setReady] = useState<{ jac: boolean; binary: boolean } | null>(null);

  useEffect(() => {
    let stop = false;
    async function tick() {
      try {
        const [logResponse, readyResponse] = await Promise.all([
          fetch("/api/log", { cache: "no-store" }),
          fetch("/api/ready", { cache: "no-store" }),
        ]);
        const logBody = await logResponse.json();
        const readyBody = await readyResponse.json();
        if (stop) return;
        setLog(typeof logBody.tail === "string" ? logBody.tail : "");
        setReady({ jac: Boolean(readyBody.jac), binary: Boolean(readyBody.binary) });
      } catch {
        if (!stop) setReady(null);
      }
    }
    void tick();
    const timer = setInterval(() => void tick(), 1000);
    return () => {
      stop = true;
      clearInterval(timer);
    };
  }, []);

  useEffect(() => {
    if (status !== "complete" && status !== "error") {
      setReport("");
      return;
    }
    let stop = false;
    fetch("/api/report", { cache: "no-store" })
      .then((response) => response.json())
      .then((body) => {
        if (!stop) setReport(typeof body.report === "string" ? body.report : "");
      })
      .catch(() => {
        if (!stop) setReport("");
      });
    return () => {
      stop = true;
    };
  }, [status]);

  const shownExecs = executions ?? 0;
  const active = starting || status === "running" || status === "triaging";
  const fraction =
    budget && budget > 0 ? Math.max(0, Math.min(1, shownExecs / budget)) : null;
  const phase =
    starting && status !== "running" && status !== "triaging" && status !== "complete"
      ? "Starting the Jac campaign"
      : status === "running"
        ? "Fuzzing riftpacket"
        : status === "triaging"
          ? "Replaying, minimizing, and classifying"
          : status === "complete"
            ? "Demo complete"
            : status === "error"
              ? "Campaign stopped with an error"
              : "Waiting to run";
  const readyCount = steps.filter((step) => step.ready).length;

  return (
    <Card className="border-[#e0d3bc] bg-[#faf7f2] shadow-none" id="demo">
      <CardHeader>
        <CardTitle className="text-base">Demo</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="max-w-3xl text-sm text-[#3f3a33]">
          Run demo starts the recorded riftpacket campaign: 80 executions, seed 1, 300 ms timeout. That is the
          same budget as <span className="font-mono text-xs">scripts/demo.sh</span>. Counts on this page are read
          from the published campaign file.
        </p>

        {ready && (!ready.jac || !ready.binary) ? (
          <ul className="space-y-1 text-sm text-[#9a4d0f]">
            {!ready.binary ? (
              <li>The riftpacket binary is not built. <span className="font-mono text-xs">scripts/build.sh</span> has to finish before a run can start.</li>
            ) : null}
            {!ready.jac ? (
              <li>The Jac runtime is not on PATH. A published state file can still be shown. A new campaign cannot start.</li>
            ) : null}
          </ul>
        ) : null}

        <div>
          <div className="mb-1 flex items-baseline justify-between gap-3 text-sm">
            <p>{phase}</p>
            <p className="font-mono text-xs text-[#5c564c]">
              {budget ? `${shownExecs.toLocaleString()} / ${budget.toLocaleString()} execs` : status}
            </p>
          </div>
          <div
            className="h-2 overflow-hidden rounded-full bg-[#e7e0d4]"
            role="progressbar"
            aria-label="Campaign executions"
            aria-valuemin={0}
            aria-valuemax={budget ?? undefined}
            aria-valuenow={budget ? shownExecs : undefined}
            aria-busy={active}
          >
            <div
              className={`h-full bg-[#0f6e6b] ${active && fraction === null ? "w-1/3 animate-pulse" : ""}`}
              style={fraction === null ? undefined : { width: `${Math.round(fraction * 100)}%` }}
            />
          </div>
        </div>

        <div>
          <p className="mb-2 text-xs text-[#5c564c]">
            Walkthrough {readyCount} / {steps.length}
          </p>
          <ol className="grid gap-2 sm:grid-cols-3">
            {steps.map((step, index) => (
              <li key={step.id}>
                <button
                  type="button"
                  onClick={step.onOpen}
                  className={`w-full rounded-md border px-2 py-2 text-left ${
                    step.ready ? "border-[#0f6e6b] bg-[#f7fbfa]" : "border-[#e4dccf] bg-white"
                  }`}
                >
                  <span className="font-mono text-[11px] text-[#5c564c]">
                    {index + 1}. {step.ready ? "ready" : "waiting"}
                  </span>
                  <span className="mt-0.5 block text-sm">{step.label}</span>
                  <span className="mt-0.5 block text-xs text-[#5c564c]">{step.hint}</span>
                </button>
              </li>
            ))}
          </ol>
        </div>

        <details className="rounded-md border border-[#e4dccf] bg-white px-3 py-2">
          <summary className="cursor-pointer text-sm">Campaign log</summary>
          <pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap font-mono text-[11px] text-[#3f3a33]">
            {log || "No campaign log yet."}
          </pre>
        </details>

        {report ? (
          <details className="rounded-md border border-[#e4dccf] bg-white px-3 py-2" id="report">
            <summary className="cursor-pointer text-sm">Campaign report</summary>
            <pre className="mt-2 max-h-80 overflow-auto whitespace-pre-wrap font-mono text-[11px] text-[#3f3a33]">
              {report}
            </pre>
          </details>
        ) : null}
      </CardContent>
    </Card>
  );
}
