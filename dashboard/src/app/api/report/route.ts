import { NextResponse } from "next/server";
import fs from "node:fs";

import { reportPath } from "@/lib/repo";

export const dynamic = "force-dynamic";

export async function GET() {
  const file = reportPath();
  if (!fs.existsSync(file)) {
    return NextResponse.json({ present: false, report: "", truncated: false });
  }
  const raw = fs.readFileSync(file, "utf8");
  const limit = 80_000;
  return NextResponse.json({
    present: true,
    report: raw.slice(0, limit),
    truncated: raw.length > limit,
  });
}
