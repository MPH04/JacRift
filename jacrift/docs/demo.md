# Demo

The live story is a local campaign against `riftpacket`, then the board.

## Prep

```bash
pip install --user -r requirements.txt
export PATH="$HOME/.local/bin:$PATH"
./scripts/build.sh
./scripts/demo.sh
```

`demo.sh` defaults to `--execs 80 --seed 1 --timeout-ms 300`. Override with `EXECS`, `SEED`, and `TIMEOUT_MS`.

Expected CLI tail when the binary and Jac runtime are present: status `complete`, then a line of executions, edges, behavior keys, and finding count. The exact integers depend on the run. They are whatever the engine counted.

Artifacts:

- `var/state.json` — schema `vectorrift.state.v1`
- `var/report.md` — the same investigation in prose
- `var/campaign/fuzz/` — events, corpus, failures, progress
- `var/campaign/minimized/` — ddmin outputs

## Dashboard

```bash
cd dashboard
npm install
npx next dev -p 43117 -H 0.0.0.0
```

The board polls `GET /api/state` once a second.

What to look at, in order:

1. Coverage novelty and behavior novelty are separate cards and separate series.
2. The check badges (`coverage guided`, `behavior independent`, `agents acted`, `reproduced`, `jac graph`) flip only when the campaign set them from measurements.
3. Findings list mixes novel behavior, suspicious divergence, and confirmed sanitizer records. The badge is the classification, not a severity color scale pretending to be CVSS.
4. Evidence shows the claim, replay match, minimized length, and hex. **Replay stored input** runs the stored argv.
5. Hypotheses show supported and contradicted rows. Arbitrary code execution is contradicted on confirmed records.
6. Lineage is the corpus ancestry for that input id.
7. Graph lists edges that touch the finding, its input, or its minimized id, plus the full graph’s node and edge counts.
8. Experiments record the note sweep and any directional sanitizer the agents scheduled.
9. Limitations at the bottom are the ones `campaign.jac` published, including the AddressSanitizer `RLIMIT_AS` note.

`POST /api/campaign` with `{"execs":120,"seed":1}` starts another run. Executions outside 1..5000 are rejected. A second start while status is `running` returns 409.

## If something is missing

| Missing | What still works | What the UI must not say |
| --- | --- | --- |
| `clang-18` | Jac unit tests that do not spawn the binary | That a sanitizer finding was observed |
| `jac` | `vrfuzz_riftpacket replay` on a saved input | That agents investigated it |
| Dashboard | `var/report.md` and the CLI summary | That the board measured anything |
| `var/state.json` | Board shows idle and the scope sentence | A previous campaign’s numbers |

## Judge path

Start from an empty `var/` if you want the idle state, run `scripts/demo.sh`, refresh the board, open the heap-buffer-overflow finding, and press replay. Then open the signed-overflow finding if the scale experiment staged it. Read the contradicted hypothesis before reading the claim as a vulnerability headline.
