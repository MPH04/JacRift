import { NextResponse } from "next/server";
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { repoRoot, statePath } from "@/lib/repo";

export const dynamic = "force-dynamic";

function run(argv: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(argv[0], argv.slice(1), { shell: false });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
      if (stdout.length > 200_000) stdout = stdout.slice(-200_000);
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
      if (stderr.length > 80_000) stderr = stderr.slice(-80_000);
    });
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
    }, 8000);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? 1, stdout, stderr });
    });
  });
}

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  const findingId = String(body.finding_id ?? "");
  if (!/^f-[a-f0-9]{8,64}$/.test(findingId)) {
    return NextResponse.json({ error: "finding_id is not a VectorRift id" }, { status: 400 });
  }
  const raw = fs.readFileSync(statePath(), "utf8");
  const state = JSON.parse(raw);
  const finding = (state.findings ?? []).find((item: { finding_id?: string }) => item.finding_id === findingId);
  if (!finding) {
    return NextResponse.json({ error: "finding is not in the current state" }, { status: 404 });
  }
  const argv = finding.replay_argv;
  if (!Array.isArray(argv) || argv.length < 4) {
    return NextResponse.json({ error: "this finding has no stored replay argv" }, { status: 400 });
  }
  const binary = String(argv[0]);
  const root = repoRoot();
  const allowedBins = ["vrfuzz_riftpacket", "vrfuzz_hostile"].map((name) =>
    path.resolve(root, "native", "build", name),
  );
  if (!allowedBins.includes(path.resolve(binary)) || argv[1] !== "replay" || argv[2] !== "--input") {
    return NextResponse.json({ error: "replay argv failed the allowlist" }, { status: 400 });
  }
  const input = path.resolve(String(argv[3]));
  const allowedRoot = path.resolve(root) + path.sep;
  if (!input.startsWith(allowedRoot)) {
    return NextResponse.json({ error: "replay input is outside the repository" }, { status: 400 });
  }
  if (!fs.existsSync(input) || !fs.existsSync(binary)) {
    return NextResponse.json({ error: "replay binary or input is missing" }, { status: 400 });
  }
  const timeout = argv[4] === "--timeout-ms" && /^\d+$/.test(String(argv[5])) ? String(argv[5]) : "500";
  const result = await run([binary, "replay", "--input", input, "--timeout-ms", timeout]);
  let event: Record<string, unknown> | null = null;
  for (const line of result.stdout.split("\n")) {
    if (line.includes("vectorrift.execution.v1")) {
      try {
        event = JSON.parse(line);
      } catch {
        event = null;
      }
    }
  }
  const matched =
    event !== null &&
    event.exit_type === finding.exit_type &&
    event.sanitizer === finding.sanitizer &&
    (event.frame === finding.frame || !finding.frame || !event.frame);
  return NextResponse.json({
    code: result.code,
    matched,
    event: event
      ? {
          exit_type: event.exit_type,
          sanitizer: event.sanitizer,
          frame: event.frame,
          input_len: event.input_len,
          execution_us: event.execution_us,
        }
      : null,
    stderr_tail: result.stderr.slice(-400),
  });
}
