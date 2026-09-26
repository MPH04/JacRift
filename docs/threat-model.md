# Threat model

JacRift analyzes a Jac repository the operator is allowed to analyze. The operator must send `authorization_confirmed: true` and `scope: "repository_only"`. Anything else is rejected before a sandbox is created.

## In scope

- `https://github.com/OWNER/REPOSITORY` URLs with no credentials, no extra path, and no non-GitHub host.
- The built-in fixture `fixture://safe-buggy`, copied from this tree.
- Local synthetic fuzzer targets `riftpacket` and `hostile` when someone explicitly runs the campaign scripts.
- Job files under `var/jobs/` and the campaign file `var/state.json`.

## Out of scope

- Scanning hosts or repositories the operator does not own.
- Credential theft, persistence, lateral movement, or malware.
- Exploit deployment, authentication attacks against other services, or destructive payloads.
- Treating a crash, a type error, or a failed test as permission to claim remote code execution.
- Executing shell commands found in a submitted README or Makefile.
- Rendering repository output as HTML.

## The repository is untrusted

| Risk | Control |
| --- | --- |
| Code runs on the JacRift host | Execution is a user namespace (`unshare`), not the parent Python process |
| Network from the target | Execution uses `--net`. Clone is a separate phase |
| Inherited cloud credentials, SSH agent, Docker socket | Environment is replaced. Those paths are hidden in the mount namespace |
| Shell injection via a tool command | Argv arrays only. Program basename allowlist |
| Reading host files from an artifact API | `read_artifact` stays inside the job workspace |
| Output flood | Stdout and stderr caps, then the pipes are drained |
| Hang | Wall-clock timeout and `RLIMIT_CPU`, then the process group is killed |
| Fork bomb | `RLIMIT_NPROC` ceiling. It stays above the current thread count so the child can start |
| Huge output files | `RLIMIT_FSIZE`. Core dumps are disabled |
| Secrets in logs | Redaction of common token shapes. Job logs are size-bounded |
| A second writer on one job | `flock` on `job.lock` plus a process lock |
| Instructions in the repository | Discovery records build files and does not run them |
| Entrypoint that shells out | Runtime skips files that mention subprocess, sockets, `eval`, `exec`, ctypes, or pty |
| Mutation aimed at another system | Mutation edits JSON fields of the job's own entrypoint input, at most six variants |
| Weak observation shown as a confirmed finding | `jac/repo_case.jac` requires replay, minimization, a source location, a supported narrow hypothesis, and a contradicted broad claim |
| Memory-safety label without a sanitizer | Contradicted, not confirmed |

`RLIMIT_AS` is unset. A tight virtual-address limit prevents CPython and Jac from starting. That is a gap relative to a full container, and it is stated here so it is not mistaken for a memory cap.

`ContainerSandboxBackend` does not fall back to the host. With no container runtime it returns an error. With a runtime present it still refuses, because this deployment does not enable nested containers.

## What the product UI can do

The console can create a job, read its state, replay a stored command for a finding, and cancel or delete a job. It cannot pass an arbitrary argv. Replay uses the command stored on that finding and the same sandbox rules.

The synthetic campaign board, if started separately, can run `jac run jac/main.jac` with a numeric budget and can replay two allowlisted binaries. It is not the repository-analysis API. A finding id there must match `f-` plus hex. Replay argv is a list.

## Evidence boundary

A `CONFIRMED_DEFENSIVE_FINDING` means the ladder's checks passed for that category: the behavior repeated, a reduced trigger still produced it, a location was named, the narrow hypothesis held, and a broader exploitability claim did not. It does not mean a CVE, a severity score, or a demonstrated compromise.

For the order-graph fixture, the narrow claim is that `COMPLETE` is returned before verification. The counter-example is the same input with `verified: true`, which does not emit the marker. The report is expected to say what was not shown.
