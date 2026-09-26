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
