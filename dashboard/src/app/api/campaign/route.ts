import { NextResponse } from "next/server";
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import {
  augmentedPath,
  campaignLogPath,
  jacBinary,
  repoRoot,
  riftpacketBinary,
  statePath,
} from "@/lib/repo";

export const dynamic = "force-dynamic";

const DEMO = { execs: 80, seed: 1, timeoutMs: 300 };

function readStatus(): string {
  try {
    const parsed = JSON.parse(fs.readFileSync(statePath(), "utf8"));
    return String(parsed?.campaign?.status ?? "");
  } catch {
    return "";
  }
}

function launch(jacBin: string, args: string[], header: string): number | undefined {
  const logPath = campaignLogPath();
  fs.mkdirSync(path.dirname(logPath), { recursive: true });
  const logFd = fs.openSync(logPath, "w");
  try {
    fs.writeSync(logFd, header);
    const child = spawn(jacBin, args, {
      cwd: repoRoot(),
      detached: true,
      stdio: ["ignore", logFd, logFd],
      shell: false,
      env: {
        ...process.env,
        PATH: augmentedPath(),
        PYTHONUNBUFFERED: "1",
      },
    });
    child.on("error", (err) => {
      fs.appendFileSync(logPath, `failed to start: ${err.message}\n`);
    });
    child.unref();
    return child.pid;
  } finally {
    fs.closeSync(logFd);
  }
}

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  const profile = String(body.profile ?? "campaign");
  if (profile !== "demo" && profile !== "campaign") {
    return NextResponse.json({ error: "profile must be demo or campaign" }, { status: 400 });
  }

  const execs = profile === "demo" ? DEMO.execs : Number(body.execs ?? 120);
  const seed = profile === "demo" ? DEMO.seed : Number(body.seed ?? 1);
  const timeoutMs = profile === "demo" ? DEMO.timeoutMs : Number(body.timeout_ms ?? 250);
  if (!Number.isInteger(execs) || execs < 1 || execs > 5000) {
    return NextResponse.json({ error: "execs must be an integer from 1 to 5000" }, { status: 400 });
  }
  if (!Number.isInteger(seed) || seed < 1 || seed > 1_000_000) {
    return NextResponse.json({ error: "seed must be a positive integer" }, { status: 400 });
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 10_000) {
    return NextResponse.json({ error: "timeout_ms must be an integer from 1 to 10000" }, { status: 400 });
  }
  if (readStatus() === "running") {
    return NextResponse.json({ error: "A campaign is already marked running." }, { status: 409 });
  }

  const root = repoRoot();
  const entry = path.join(root, "jac", "main.jac");
  if (!fs.existsSync(entry)) {
    return NextResponse.json({ error: "Jac entrypoint is missing." }, { status: 500 });
  }
  const jac = jacBinary();
  if (!jac) {
    return NextResponse.json(
      { error: "Jac runtime is not on PATH. Install requirements.txt before running the demo." },
      { status: 500 },
    );
  }
  if (!fs.existsSync(riftpacketBinary())) {
    return NextResponse.json(
      { error: "Missing native/build/vrfuzz_riftpacket. Run scripts/build.sh." },
      { status: 500 },
    );
  }

  const args = [
    "run",
    entry,
    "--",
    "campaign",
    "--execs",
    String(execs),
    "--seed",
    String(seed),
    "--timeout-ms",
    String(timeoutMs),
  ];
  const header = `profile=${profile} execs=${execs} seed=${seed} timeout_ms=${timeoutMs}\n`;
  const pid = launch(jac, args, header);
  return NextResponse.json({ started: true, profile, execs, seed, timeout_ms: timeoutMs, pid });
}
