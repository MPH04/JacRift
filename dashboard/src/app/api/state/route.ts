import { NextResponse } from "next/server";
import fs from "node:fs";

import { statePath } from "@/lib/repo";
import { EMPTY_STATE } from "@/lib/types";

export const dynamic = "force-dynamic";

export async function GET() {
  const file = statePath();
  if (!fs.existsSync(file)) {
    return NextResponse.json({
      ...EMPTY_STATE,
      campaign: {
        ...EMPTY_STATE.campaign,
        status: "idle",
        error: "",
      },
    });
  }
  try {
    const raw = fs.readFileSync(file, "utf8");
    const parsed = JSON.parse(raw);
    return NextResponse.json(parsed);
  } catch {
    return NextResponse.json(
      {
        ...EMPTY_STATE,
        campaign: {
          status: "error",
          error: "var/state.json could not be parsed. It is not being shown as a campaign.",
          target_id: "riftpacket",
        },
      },
      { status: 500 },
    );
  }
}
