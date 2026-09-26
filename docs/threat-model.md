# Threat model

VectorRift tests software the operator is allowed to test. The shipped targets are synthetic programs in this repository: `riftpacket` (intentionally incorrect parser) and `hostile` (isolation fixture).

## In scope

- Local builds of those targets.
- Seed, mutated, and minimized inputs stored under this repository or `var/`.
- Sanitizer reports produced by those builds.
- The dashboard process on the same machine, talking only to local files and local binaries.

## Out of scope

- Scanning hosts the operator does not own.
- Credential theft, persistence, botnet operation, or deployment of malware.
- Treating a crash as permission to attack a third-party system.
- Rendering target output as HTML or passing it to a shell.

Demonstrations use dummy protocol bytes (`VR` plus opcodes). They do not embed real secrets.

## The target is hostile to the fuzzer

Assumptions attacked on purpose:

| Attack | Control |
| --- | --- |
| Huge stderr | Parent caps the excerpt and keeps draining the pipe |
| Hang | Wall-clock timeout, then `SIGKILL`; child also has `RLIMIT_CPU` |
| `abort()` | Recorded as `CRASH`, signal 6, empty sanitizer class |
| Path or shell metacharacters in an input id | Ids are hex. Replay argv is a list, never a shell string |
| Finding id that looks like a path | Dashboard requires `f-` plus 8–64 hex digits |
| Replay binary outside `native/build` | Allowlist of two basenames |
| Replay input outside the repo | `path.resolve` prefix check |
| ANSI and markup in excerpts | Jac sanitizers before publish |
| Claims that name a CVE, CVSS, zero-day, or exploitability score | Publish refuses the state |
| Second campaign overlapping the first | `flock` plus dashboard 409 |
| Coverage map reset mistaken for “no new edges” | `compare` runs both inputs in one process |
| Engine edges counted as target coverage | `trace-pc-guard` only on the target translation unit |
| Frame parser matching prose (“in type 'int32_t'”) | Only `#` stack frames and `file.c:line` |

`RLIMIT_AS` is intentionally unset. AddressSanitizer reserves a large virtual range; applying the limit kills the child before the target runs. CPU, file size, core dumps, wall clock, and output size are the bounds that were tested. The published limitations say this in the product, not only here.

## What a user can do with the dashboard

The campaign button runs `jac` against this repo’s entrypoint with a numeric budget. The replay button runs an allowlisted binary. Neither endpoint accepts a free-form command. A user who can already write to the repository can of course change the source. The API is not a general shell.

## Evidence boundary

A confirmed finding in this product means: a local sanitizer reported a specific bug class, the same signature came back on replay, and a minimized input still produced it. It does not mean a CVE, a severity score, or demonstrated code execution. The skeptic walker records the contradiction explicitly.
