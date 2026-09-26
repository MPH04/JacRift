# Architecture

JacRift answers a narrow question: given an authorized Jac repository, what failed, can it be repeated, what smaller trigger still fails, and which explanation the evidence supports.

The product entrypoint is `jac start main.jac`. There is one UI for repository jobs. The Next.js board remains only for the synthetic fuzzing fixture.

## Job path

```text
Authorized repository URL
        ↓
validate_submission          jrlib/validate.py
        ↓
job directory                var/jobs/JR-XXXXXX/
        ↓
sandbox create               jrlib/sandbox.py
        ↓
copy fixture or git clone
        ↓
discover                     jrlib/discover.py  → manifest.json
        ↓
jac check / jac test / jac run / bounded JSON mutation
        ↓
replay and minimize          jrlib/reproduce.py
        ↓
jac run jac/investigate.jac  graph + findings.json + report.md
```

`jrlib/pipeline.py` is the only place that advances a job. Tool errors are written into `state.json` and `events.jsonl`. If the Jac investigation command fails, the job status is `FAILED`. Python does not invent findings to hide that.

`state.json` uses `jacrift.job.v1`. The synthetic campaign file `var/state.json` still uses `vectorrift.state.v1`. Loaders accept that file and expose it as `jacrift.state.v2` with `compat_from`. Execution events on disk stay `vectorrift.execution.v1`; `jacrift.execution.v1` parses and is stored as the original schema. See [legacy-names.md](legacy-names.md).

## Who owns what

| Piece | Owns | Does not own |
| --- | --- | --- |
| `jrlib/validate.py` | URL shape, authorization boolean, scope | Cloning |
| `jrlib/jobs.py` | Directories, lock, phases, redacted logs | Classification |
| `jrlib/sandbox.py` | Process isolation and argv execution | Hypothesis text |
| `jrlib/discover.py` | File inventory | Running README commands |
| `jrlib/analyze.py` | `jac check`, `jac test`, `jac run`, bounded mutation | Confirming a finding |
| `jrlib/reproduce.py` | Replay counts and JSON-key deletion | Status ladder |
| `jac/repo_case.jac` | Ladder from `OBSERVED` to `CONFIRMED_DEFENSIVE_FINDING` | Sandbox |
| `jac/investigate.jac` | Per-job graph, report, `findings.json` | HTTP |
| `server.jac` | `POST /function/api_*` | Path routing |
| `jrlib/http_facade.py` | `/api/jobs` on the Jac server | Investigation |
| `components/console.cl.jac` | Submit, progress, findings, graph, log, report | A second backend |

## HTTP

Jaclang 0.16 serves public functions at `POST /function/<name>`. `@restspec(path=...)` is stored and not consulted by the request handler. `main.jac` calls `install_job_routes()` at load, which wraps `JacAPIServer.create_handler` and serves:

```text
POST   /api/jobs
GET    /api/jobs
GET    /api/jobs/{id}
GET    /api/jobs/{id}/log|events|findings|report
POST   /api/jobs/{id}/reproduce
DELETE /api/jobs/{id}
```

Unmatched paths still go to the Jac client. `GET /api/jobs` is intercepted before the SPA fallback, so the console receives JSON.

## Sandbox backends

`SandboxBackend` is the interface (`create`, `clone_repository`, `inspect`, `run`, `read_artifact`, `collect_results`, `destroy`). `backend_for()` reads `JACRIFT_SANDBOX`:

- `jachammer` (default) and `local` — `LocalSandboxBackend` / `JacHammerSandboxBackend`
- `container` — `ContainerSandboxBackend`, which fails closed

The JacHammer image used here has `unshare` and does not have a nested container runtime. Execution adds `--net`. Clone does not. The child `preexec` only applies rlimits; it does not spawn another process (that deadlocks under `fork`).

## Evidence

Normalized evidence carries `evidence_id`, `job_id`, `source`, `category`, command, exit code, file, line, stdout, stderr, and a timestamp. Categories used by the fixture include `JAC_SYNTAX_ERROR`, `JAC_TYPE_ERROR`, `BROKEN_IMPORT`, `TEST_FAILURE`, `JAC_RUNTIME_ERROR`, `STATE_INVARIANT_FAILURE`, and `WALKER_FAILURE`.

`jac/investigate.jac` builds graph nodes for the repository, job, executions, evidence, failures, reproducers, hypotheses, experiments, findings, and source locations. Edges use `produced`, `observed`, `derived_from`, `reproduces`, `minimized_to`, `located_at`, `supports`, `contradicts`, and `tests`. A support walk counts supported versus contradicted hypotheses. Hypotheses are not also linked from the root, which would double-count.

The graph database is created with the job directory as the working directory, so jobs do not share a graph.

## UI stages

The console shows display stages derived from the phase: Repository Received, Sandbox Created, Repository Cloned, Project Discovered, Static Analysis, Tests, Runtime Analysis, Reproduction, Investigation, Complete. Metrics come from the job state: Jac files, tests discovered, checks executed, runtime executions, observations, reproduced failures, findings.

## Synthetic campaign fixture

`native/` plus `jac/campaign.jac` is a local fuzzing workbench for two labeled targets, `riftpacket` and `hostile`. It is not invoked by a repository job.

The C engine executes and measures. Jac classifies. `vectorrift.execution.v1` is one JSON object per line. Confirmation in that ladder still requires a matching replay, a minimized input, a recognized sanitizer class (`heap-buffer-overflow` or `signed-integer-overflow`), a supported narrow hypothesis, and a contradicted “arbitrary code execution” hypothesis.

Coverage flags stay on the target translation unit only. `RLIMIT_AS` stays unset because AddressSanitizer reserves a large virtual range. The dashboard in `dashboard/` reads `var/state.json`, starts `jac run jac/main.jac` for that campaign, and replays only `vrfuzz_riftpacket` or `vrfuzz_hostile` under `native/build`.

That board is a fixture viewer. Repository analysis does not go through it.
