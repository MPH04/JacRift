# JacRift

JacRift is a defensive investigation platform for authorized Jac repositories.

## Vision

The question JacRift is built to answer:

> Given an authorized Jac repository, can we safely analyze it, detect meaningful failures, reproduce them, determine what evidence supports them, and present a defensible explanation to a developer?

Detecting something abnormal is not the same as proving what happened. The product is not a path from a repository, through a model, to a vulnerability label. It is a path from a controlled observation to an explanation a developer can inspect.

```text
Repository
        ↓
Controlled observation
        ↓
Evidence
        ↓
Reproduction
        ↓
Minimization
        ↓
Investigation
        ↓
Hypothesis
        ↓
Counter-evidence
        ↓
Defensible finding
```

The philosophy is **Observation → Evidence → Reproduction → Explanation**. A weak observation stays a weak observation until the evidence earns a stronger claim.

A result should not read:

```text
Possible vulnerability found.
```

It should try to read:

```text
Something unusual happened.
We reproduced it.
We reduced it to a smaller trigger.
We identified the relevant source location.
We constructed a narrow hypothesis.
We tested supporting and contradictory evidence.
Here is what the evidence supports.
Here is what remains unknown.
```

Every finding is expected to answer: what happened, where, whether it repeats, what triggers it, what supports the explanation, what contradicts it, and what is still unknown. Findings become stronger only as evidence accumulates:

```text
OBSERVED
→ ANOMALOUS
→ REPRODUCIBLE_FAILURE
→ MINIMIZED_FAILURE
→ SUPPORTED_HYPOTHESIS
→ CONFIRMED_DEFENSIVE_FINDING
```

A confirmed finding needs repeatable behavior, a minimal trigger, a source location, a narrow hypothesis the evidence supports, and a record of what would make that explanation wrong. JacRift does not jump from an observation to a confirmed finding, and it does not invent exploitability. Remote code execution, account takeover, and complete compromise are not default conclusions.

The differentiator is the evidence that turns a strange behavior into an explainable, reproducible finding.

## What JacRift does

- Repository inspection inside a disposable sandbox
- Jac static analysis (`jac check`)
- Recognized tests (`jac test`)
- Controlled runtime execution of safe entrypoints
- Bounded mutation of identified application inputs
- Replay and minimization
- An investigation graph in Jac
- Narrow hypotheses and a skeptic pass
- A structured defensive finding and a written report

## What JacRift does not claim

- Guaranteed vulnerability detection
- Automatic exploitation
- Scanning repositories you do not own or have authorization to test
- Automatic CVE generation
- Automatic business-impact assessment
- A replacement for human security review

JacRift does not emit claims such as remote code execution, account takeover, or complete compromise. A broad claim of that kind is recorded as contradicted.

## Product flow

Open the app with `jac start` (see [JacHammer deployment](#jachammer-deployment)). Submit a repository and confirm authorization:

```text
https://github.com/OWNER/REPOSITORY
```

or the built-in demonstration fixture:

```text
fixture://safe-buggy
```

The checkbox must be checked. The request is:

```json
{
  "repository_url": "fixture://safe-buggy",
  "authorization_confirmed": true,
  "scope": "repository_only"
}
```

Rejected before any clone or copy: malformed URLs, unsupported schemes (`http`, `ssh`, `git@`, `file`), non-GitHub hosts, extra path segments, credentials in the URL, a missing authorization boolean, and any scope other than `repository_only`.

Each submission is an independent job, `JR-` plus six hex characters, under `var/jobs/<id>/`:

```text
repository/  manifest.json  state.json  events.jsonl
findings.json  report.md  graph.json  logs/  artifacts/  job.lock
```

Phases run from `QUEUED` through sandbox preparation, clone or copy, inspection, static analysis, tests, runtime, bounded mutation, reproduction, minimization, and triage. Terminal states are `COMPLETE`, `FAILED`, and `CANCELLED`. A tool failure is stored on the job. It does not take down the server.

## Architecture

Python `jrlib` owns jobs, the sandbox, discovery, tool execution, and the HTTP table. Jac owns the evidence ladder and the investigation graph for a repository job. The older synthetic fuzzer remains a labeled fixture; it is not the product.

```text
jac start main.jac
    ├── client UI          components/console.cl.jac
    ├── /api/jobs          jrlib/http_facade.py
    ├── /function/api_*    server.jac  →  jrlib/api.py
    └── job pipeline       jrlib/pipeline.py
            ├── sandbox    jrlib/sandbox.py
            ├── discovery  jrlib/discover.py
            ├── analysis   jrlib/analyze.py
            ├── replay     jrlib/reproduce.py
            └── graph      jac/investigate.jac + jac/repo_case.jac
```

Detail is in [docs/architecture.md](docs/architecture.md). The threat model is in [docs/threat-model.md](docs/threat-model.md). Legacy names are in [docs/legacy-names.md](docs/legacy-names.md).

## JacHammer deployment

This environment serves Jac apps with `jac start`. There is no separate Next.js process in the product path.

```bash
pip install --user -r requirements.txt
export PATH="$HOME/.local/bin:$PATH"
jac install
jac start main.jac --port 8000
```

Open `http://127.0.0.1:8000/`. The page title is JacRift. `GET /healthz` is the process probe.

`jaclang==0.16.7` does not dispatch `@restspec` custom paths. Job routes are installed onto the Jac request handler when `main.jac` loads:

| Method | Path | Body |
| --- | --- | --- |
| POST | `/api/jobs` | `repository_url`, `authorization_confirmed`, `scope` |
| GET | `/api/jobs` | |
| GET | `/api/jobs/{id}` | job snapshot: stages, metrics, findings, graph, log, report |
| GET | `/api/jobs/{id}/log` | |
| GET | `/api/jobs/{id}/events` | |
| GET | `/api/jobs/{id}/findings` | |
| GET | `/api/jobs/{id}/report` | |
| POST | `/api/jobs/{id}/reproduce` | `finding_id` |
| DELETE | `/api/jobs/{id}` | cancel if running, delete if terminal |

The same operations exist as `POST /function/api_create_job` and the other `api_*` functions. Responses there use Jac's envelope `{ok, data: {result}}`. `/api/jobs` returns the result object directly.

A CLI without the server:

```bash
python3 -m jrlib.cli --repository fixture://safe-buggy
```

## Sandbox

Submitted repositories are untrusted. This JacHammer environment has no Docker or Podman socket, so the execution backend is a disposable user namespace (`unshare --user --map-root-user --pid --fork --mount --mount-proc`), not a nested container. `ContainerSandboxBackend` fails closed when a container runtime is absent, and it stays disabled when one is present.

- Clone (GitHub `https` only) may use the network. Execution does not (`--net`).
- The fixture is copied from this tree. It is not fetched.
- Commands are argv arrays. `shell=True` is not used.
- The child environment is replaced: `PATH`, a job-local `HOME` and `TMPDIR`, `LANG=C`, `GIT_TERMINAL_PROMPT=0`, and `PYTHONPATH` pointed at the host user site so `jac` can import `jaclang`. Host secrets are not forwarded.
- Credential directories and the Docker socket are hidden inside the mount namespace.
- `read_artifact` rejects paths outside the job workspace.
- Allowed programs are `jac`, `python3`, and `python`, and only from `/usr/bin`, `/bin`, or `~/.local/bin` when the path is absolute.
- Limits: CPU time, file size, core dumps disabled, open files, process count, wall-clock timeout, and capped stdout/stderr. `RLIMIT_AS` is not set; Jac and CPython need a large virtual address space, and a tight address limit kills the interpreter before the target runs.
- Process-count ceiling is above the current thread count. A limit below that cannot `fork`.
- Logs are size-bounded and redacted (cloud key shapes, GitHub tokens, bearer tokens).

`JACRIFT_SANDBOX` selects the backend name. The default is `jachammer`, which uses the same local namespace backend.

## Repository discovery and analysis

Discovery lists Jac files, tests, Python files, dependency manifests, and build files. It does not execute README commands or Makefiles. Those paths are recorded and skipped.

Static analysis runs `jac check` per non-test Jac file. Tests run `jac test` when a `tests/` tree exists. Runtime runs `jac run` only for entrypoints that do not reference subprocess, sockets, `eval`, `exec`, ctypes, or a pty, and that are under 20KB. Bounded mutation edits JSON fields on those inputs (at most six variants). It does not target other hosts.

Interesting failures are replayed five times. A failure is reproducible when there are at least three attempts and at least four of every five attempts match. JSON object keys are dropped, including the last key, while the failure signature holds. An empty object is kept when the program defaults still fail. A single `jac check` / `jac test` / `jac run` command is already one command; minimization records that as `diagnostic_command` and does not rewrite the source file. The finding limitations say so.

## Evidence ladder

Repository findings move through:

```text
OBSERVED
→ ANOMALOUS
→ REPRODUCIBLE_FAILURE
→ MINIMIZED_FAILURE
→ SUPPORTED_HYPOTHESIS
→ CONFIRMED_DEFENSIVE_FINDING
```

`jac/repo_case.jac` is the gate. Confirmation needs a reproducible replay, a minimized trigger, a narrow supported hypothesis, a contradicted broad hypothesis, and a source location. Memory-safety and undefined-behavior labels without a sanitizer diagnostic are contradicted, not confirmed.

The synthetic riftpacket campaign keeps its own ladder in `jac/classify.jac` (`NOVEL_BEHAVIOR` through `CONFIRMED_SECURITY_FINDING`). That ladder is for the local fuzzer fixture, not for repository jobs.

## Demonstration fixture

`fixtures/safe_buggy` is a **TEST / DEMONSTRATION FIXTURE**. It is excluded from the host `jac check` by `.jacignore`. Defects are harmless and local: a type mismatch, a syntax error, a missing import, a failing unit test, an index exception, a walker that reports `WALKER_FAILURE`, and an order graph that can enter `COMPLETE` before verification.

Expected on a successful job: status `COMPLETE`, a confirmed `STATE_INVARIANT_FAILURE` on `checkout/order_graph.jac`, a minimized JSON input, a contradicted counter-check (`verified: true` removes the marker), and a report that says what remains unknown.

The native targets under `native/` (`riftpacket`, `hostile`) are also **TEST / DEMONSTRATION FIXTURES** for the older campaign. They are not the repository-analysis product. The Next.js app in `dashboard/` is the board for that campaign only. Its page is labeled as such. Start it separately if you are inspecting `var/state.json`; it is not served by `jac start`.

## Tests

```bash
export PATH="$HOME/.local/bin:$PATH"
./scripts/test.sh
```

That runs `jac test` on each file in `jac/` and `python3 -m unittest discover -s tests`. Engine tests skip when the native binaries are absent. Dashboard API tests run only when `VECTORRIFT_DASHBOARD_URL` is set.

A fixture job without the UI:

```bash
python3 -m unittest tests.test_pipeline.PipelineTests.test_fixture_reaches_confirmed_finding
```

## Layout

```text
main.jac              jac start entry (API + UI)
server.jac            Jac function endpoints
components/           repository console
jrlib/                jobs, sandbox, discovery, analysis, HTTP routes
jac/                  investigation core, including repository cases
fixtures/safe_buggy   labeled demonstration repository
native/               synthetic fuzzer fixtures
dashboard/            synthetic campaign board (not the product UI)
corpus/seeds/         riftpacket seeds
docs/                 architecture, threat model, demo, legacy names
var/jobs/             generated job state (gitignored)
```

## Known limitations

- Isolation is a user namespace on this host, not a separate VM or container image. A kernel that allows user namespaces is required. `unshare` must exist.
- GitHub cloning is implemented and separated from the network-off execution phase. A live clone of an arbitrary third-party repository was not part of the automated fixture test.
- Build scripts inside a submitted repository are not run. Projects that need a custom build before `jac check` will report that skip, not a guessed shell command.
- Diagnostic commands are treated as already-minimal triggers. Byte-level minimization applies to JSON inputs.
- The investigation graph view is a selectable node list with the edges between them, not a force-directed canvas.
- One analysis job runs its tools sequentially. The server can hold more than one job directory; tool runs are not a distributed queue.
- `RLIMIT_NPROC` is per user id and counts threads. The ceiling is loose on purpose.
- The synthetic campaign's `vectorrift.state.v1` file and `vrfuzz_*` binary names are unchanged. See [docs/legacy-names.md](docs/legacy-names.md).
