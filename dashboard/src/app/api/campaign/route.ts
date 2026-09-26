import { NextResponse } from "next/server";
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { repoRoot, statePath } from "@/lib/repo";

export const dynamic = "force-dynamic";

function readStatus(): string {
  try {
    const parsed = JSON.parse(fs.readFileSync(statePath(), "utf8"));
    return String(parsed?.campaign?.status ?? "");
  } catch {
    return "";
  }
}

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  const execs = Number(body.execs ?? 120);
  const seed = Number(body.seed ?? 1);
  if (!Number.isInteger(execs) || execs < 1 || execs > 5000) {
    return NextResponse.json({ error: "execs must be an integer from 1 to 5000" }, { status: 400 });
  }
  if (!Number.isInteger(seed) || seed < 1 || seed > 1_000_000) {
    return NextResponse.json({ error: "seed must be a positive integer" }, { status: 400 });
  }
  if (readStatus() === "running") {
    return NextResponse.json({ error: "A campaign is already marked running." }, { status: 409 });
  }
  const root = repoRoot();
  const jac = path.join(root, "jac", "main.jac");
  if (!fs.existsSync(jac)) {
    return NextResponse.json({ error: "Jac entrypoint is missing." }, { status: 500 });
  }
  const child = spawn(
    "jac",
    ["run", jac, "--", "campaign", "--execs", String(execs), "--seed", String(seed), "--timeout-ms", "250"],
    {
      cwd: root,
      detached: true,
      stdio: "ignore",
      shell: false,
      env: {
        ...process.env,
        PATH: `${process.env.HOME ?? ""}/.local/bin:${process.env.PATH ?? ""}`,
      },
    },
  );
  child.unref();
  return NextResponse.json({ started: true, execs, seed, pid: child.pid });
}
