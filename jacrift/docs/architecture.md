# Architecture

VectorRift splits “run the target” from “decide what the run means.” The C engine executes and measures. Jac classifies, schedules follow-ups, and publishes the investigation.

```text
                    ┌─────────────────────┐
                    │    Target Program   │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │ Instrumented Harness│
                    │ LLVM / Sanitizers   │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │ Coverage Fuzzer     │
                    └──────────┬──────────┘
                               │
                 execution + behavioral events
                               │
                    ┌──────────▼──────────┐
                    │ VectorRift Jac Core │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │ Investigation Graph │
                    └──────────┬──────────┘
                               │
             ┌─────────────────┼─────────────────┐
             │                 │                 │
      Reproduction        Skeptic Agent     Experiment Agent
             │                 │                 │
             └─────────────────┼─────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │ Dashboard / Report  │
                    └─────────────────────┘
```

## Boundaries

| Piece | Owns | Does not own |
| --- | --- | --- |
| `riftpacket.c` / `hostile.c` | `vr_target_execute`, `vr_emit` | Mutation, corpus policy, claims |
| `exec.c` | Fork isolation, sanitizer callbacks, coverage bitmap, behavior trace | Finding classification |
| `campaign.c` | Seeds, mutations, retention, replay, ddmin, `compare`, JSONL | Graph, hypotheses, report |
| `jac/campaign.jac` | Orchestration, ingest, second-pass experiments, publish | Forking the target itself |
| `dashboard/` | Render `var/state.json`, start `jac run`, allowlisted replay | Scoring, classification |

## Event schema

`vectorrift.execution.v1` is one JSON object per line. Jac’s `parse_execution` rejects a wrong schema, a huge line, an unknown `exit_type`, and non-object events. Fields the UI depends on include `exit_type` (`NORMAL`, `CRASH`, `TIMEOUT`, `SANITIZER`), `sanitizer`, `frame`, `new_edges`, `behavior_new`, `fingerprint`, `execution_us`, `stderr_truncated`, `stderr_excerpt`, and `events`.

Excerpt and event strings are passed through `sanitize_token` / ANSI stripping before they enter the graph. The native side also charset-filters `vr_emit` arguments into the shared trace.

`vectorrift.state.v1` is the published campaign. `vectorrift.minimize.v1` is the ddmin result.

## Coverage

Compile only the target translation unit with `-fsanitize-coverage=trace-pc-guard`. Engine objects get AddressSanitizer and UndefinedBehaviorSanitizer and do not get `trace-pc-guard`. Callbacks live in the engine. The bitmap is `MAP_SHARED`.

An earlier build instrumented every translation unit. Guard counts then included engine edges and overstated “target” coverage. That split is the correction. Counts are reported as guards hit versus guards installed, never as a percentage of source.

`run` sets `symbolize=0` so a crash does not pay for llvm-symbolizer on every hit. `replay` and `minimize` keep `symbolize=1` so the frame used as evidence is symbolized. Duplicate failure signatures are not retained in the corpus.

## Behavior

Tracked emit kinds are `transition`, `semantic`, `invariant`, and `op` (`op` forces the third field to `-`). The fingerprint is FNV-1a 64 over the sequence. Jac’s `BehaviorBook` uses the same algorithm. A campaign records disagreements between the engine key count and the Jac recount.

`compare --before A --input B` executes A, then B, with map updates left on, and prints B’s event. That is the measurement for “same edges, new behavior.”

## Evidence ladder

`NOVEL_BEHAVIOR` → `SUSPICIOUS_DIVERGENCE` → `CAPTURED` → `REPRODUCIBLE_FAILURE` → `SECURITY_HYPOTHESIS` → `CONFIRMED_SECURITY_FINDING`.

Confirmation requires a matching replay, a minimized input that still matches, a recognized sanitizer class (`heap-buffer-overflow` or `signed-integer-overflow`), a supported narrow hypothesis, and a contradicted “arbitrary code execution” hypothesis. The claim sentence includes “No control-flow hijack was demonstrated.”

## Graph

Nodes: target, input, execution, finding, hypothesis. Edges: `MUTATED_FROM`, `EXECUTED_ON`, `TRIGGERED`, `SUPPORTS`, `CONTRADICTS`, `MINIMIZED_TO`.

Walkers:

- `ClusterWalk` groups findings by signature.
- `AncestryWalk` follows mutation parents.
- `EvidenceWalk` counts supported versus contradicted hypotheses.

The graph database is `jac/.jac/data/`. `reset_graph()` deletes nodes reachable from `root` at the start of a campaign so a second run does not double the investigation.

## Campaign lifecycle

1. Take an exclusive flock on `var/campaign.lock`. A second start fails clearly.
2. Spawn `vrfuzz_riftpacket run` with the seed directory, budget, and timeout. Poll `progress.json` into `var/state.json` while status is `running`.
3. Ingest events. Retain corpus rows. Open findings for new semantic or transition keys, invariants, and sanitizer signatures. Invariant keys are not also filed as generic novel-behavior findings.
4. Replay captured failures. Minimize when the signature matches. Reclassify.
5. Run directional experiments the fuzzer has not already settled (note sweep, length stretch, scale overflow, data-before-auth). Stage new sanitizer results and run reproduction again.
6. Walk the graph. Set `checks` only from those measurements. Write `var/report.md` and `var/state.json`.

## Dashboard

Next.js reads the state file. `POST /api/campaign` spawns `jac run jac/main.jac` with `shell: false`, detached, and a bounded exec/seed range. It returns 409 if status is already `running`. `POST /api/reproduce` checks the finding id, binary basename, and input path before `spawn`.

## Dependency versions exercised here

- jaclang 0.16.7
- Ubuntu clang 18.1.3
- Next.js 15.5.26, React 19.1
- Sanitizer runtime from `libclang-rt-18-dev`

Jaseci cloud deploy and MemorySanitizer were not exercised. They are future work in the README, not features of this tree.
