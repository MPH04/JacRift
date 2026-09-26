# Decisions

Each decision records the proposal, the attack, the test, and the limitation that remains.

## Split coverage instrumentation

Proposal: one Clang link line with sanitizers and `trace-pc-guard` on every file.
Attack: engine branches become “coverage,” so a fuzzer can look productive while the target stands still. Sanitizer instrumentation also adds guards that are not source lines.
Test: self-test guard count on the target-only build (`guards=66` for riftpacket, `guards=29` for hostile).
Revised: coverage flags only on the target object. Report “N of M guards.”
Remains: M changes if Clang or the sanitizer pass changes. Do not compare guard counts across compilers.

## Jac owns classification

Proposal: print sanitizer text from C and call it a finding.
Attack: a crash string can be mis-framed, a normal invariant can be called memory corruption, and a model sentence can upgrade the label.
Test: Jac tests in `classify.jac` and `hypotheses.jac`. Publish scans finding JSON for forbidden claim tokens.
Revised: confirmation is a gate in Jac. C emits events only.
Remains: the gate recognizes two bug classes by string (`heap-buffer-overflow`, `signed-integer-overflow`). A new sanitizer class stays `REPRODUCIBLE_FAILURE` until the gate learns it. That is intentional.

## Deterministic agents

Proposal: call a language model to explain the crash.
Attack: the explanation becomes the evidence, and the demo depends on a network and a key.
Test: campaign `agents` list shows reproduction, minimization, skeptic, and next-experiment actions with measured details (lengths, frames, experiment observations).
Revised: rules and walkers only.
Remains: the agents do not invent new bug classes. They schedule a fixed menu of experiments. That is weaker than a planner and easier to audit.

## Dashboard is a view plus two spawn paths

Proposal: the board shells out to whatever `replay_argv` contains.
Attack: a poisoned state file becomes remote command execution if the browser can hit the API.
Test: `POST /api/reproduce` rejects non-hex finding ids. The server resolves the binary against two names and the input against the repo root. `shell` is false.
Revised: allowlist as implemented in `dashboard/src/app/api/reproduce/route.ts`.
Remains: anyone who can edit `var/state.json` on the server can point the allowlisted binary at any file inside the repo. They cannot select a different binary or a shell.

## Single worker

Proposal: parallel fork-server fuzzing.
Attack: shared coverage maps and the Jac graph writer race, and the demo becomes harder to replay.
Test: flock on `var/campaign.lock`, and the dashboard returns 409 when status is `running`.
Revised: one campaign process.
Remains: execs/sec is one core. The limitations line says so.

## libFuzzer stays a side binary

Proposal: replace `vrfuzz` with libFuzzer.
Attack: libFuzzer does not emit the versioned event schema, so Jac would parse its log. That parser would be the next injection surface, and coverage guidance would be real only for the native TU — which is already true of `vrfuzz`.
Test: two libFuzzer runs recorded in `docs/experiments.md` (exit 0 after 40 runs, exit 1 on the overflow).
Revised: keep `riftpacket_libfuzzer` as a check that LLVM’s engine also sees the target. The campaign does not parse libFuzzer output.
Remains: two engines can drift. The product claim of coverage guidance refers to `vrfuzz` plus `trace-pc-guard`, and the README says the libFuzzer binary is separate.
