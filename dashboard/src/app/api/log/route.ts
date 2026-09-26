import { NextResponse } from "next/server";
import fs from "node:fs";

import { campaignLogPath } from "@/lib/repo";

export const dynamic = "force-dynamic";

export async function GET() {
  const file = campaignLogPath();
  if (!fs.existsSync(file)) {
    return NextResponse.json({ present: false, tail: "", bytes: 0 });
  }
  const raw = fs.readFileSync(file, "utf8");
  return NextResponse.json({
    present: true,
    tail: raw.slice(-8_000),
    bytes: Buffer.byteLength(raw),
  });
}
