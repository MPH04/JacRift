import { NextResponse } from "next/server";
import fs from "node:fs";

import { jacBinary, riftpacketBinary, statePath } from "@/lib/repo";

export const dynamic = "force-dynamic";

export async function GET() {
  return NextResponse.json({
    jac: jacBinary() !== null,
    binary: fs.existsSync(riftpacketBinary()),
    state: fs.existsSync(statePath()),
  });
}
