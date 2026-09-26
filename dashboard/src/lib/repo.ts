import fs from "node:fs";
import path from "node:path";

export function repoRoot(): string {
  const candidates = [
    path.resolve(process.cwd(), ".."),
    path.resolve(process.cwd()),
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(path.join(candidate, "jac", "main.jac"))) {
      return candidate;
    }
  }
  return candidates[0];
}

export function statePath(): string {
  return path.join(repoRoot(), "var", "state.json");
}

export function campaignLogPath(): string {
  return path.join(repoRoot(), "var", "campaign.log");
}

export function reportPath(): string {
  return path.join(repoRoot(), "var", "report.md");
}

export function augmentedPath(): string {
  return `${process.env.HOME ?? ""}/.local/bin${path.delimiter}${process.env.PATH ?? ""}`;
}

export function jacBinary(pathEnv = augmentedPath()): string | null {
  for (const dir of pathEnv.split(path.delimiter)) {
    if (!dir) continue;
    const candidate = path.join(dir, "jac");
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      return candidate;
    } catch {
      continue;
    }
  }
  return null;
}

export function riftpacketBinary(): string {
  return path.join(repoRoot(), "native", "build", "vrfuzz_riftpacket");
}
