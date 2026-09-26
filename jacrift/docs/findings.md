# Findings

Every discovery sits on an evidence ladder. The labels are not severities.

| Classification | Meaning |
| --- | --- |
| `NOVEL_BEHAVIOR` | A behavioral key the campaign had not seen. The process exited normally. |
| `SUSPICIOUS_DIVERGENCE` | A target invariant fired (`data_before_auth`, `auth_without_open`) and the process still exited normally. That is a protocol divergence, not a memory-safety proof. |
| `CAPTURED` | Crash, sanitizer, or timeout saved to disk. Replay has not matched yet. |
| `REPRODUCIBLE_FAILURE` | Replay matched. Minimization has not yet preserved the signature, or the class is not one the confirmer recognizes. |
| `SECURITY_HYPOTHESIS` | A narrow cause is plausible and not yet confirmed by the full gate. |
| `CONFIRMED_SECURITY_FINDING` | Replay matched, minimized input still matches, the sanitizer class string is present, the narrow hypothesis is supported, and “arbitrary code execution” is contradicted. |

Agent text cannot move a record up the ladder. `classify.jac` reads replay flags, the minimized signature, and the error class.

## What confirmation says

For the length bug, the claim shape is:

> Deterministic heap-buffer-overflow reported by the address sanitizer in consume_length. The minimized input still triggers the same signature. No control-flow hijack was demonstrated.

For the scale bug:

> Deterministic signed-integer-overflow reported by the undefined sanitizer in riftpacket:71. The minimized input still triggers the same signature. No control-flow hijack was demonstrated.

Both sentences are templates filled from measured sanitizer class and frame. They are not exploitability writeups.

## What the demo target actually does

`riftpacket` is a tiny stateful parser. Magic is `VR`. Opcodes include open (`O`), auth (`A`), data (`D`), close (`C`), note (`N`), length (`L`), and scale (`S`).

Seeded defects, both local and intentional:

- `consume_length` trusts a big-endian u16 length and copies that many bytes out of a buffer sized to the actual input. AddressSanitizer reports a heap-buffer-overflow. A minimized example observed in campaign seed 1 was `VRLCD` (5 bytes), reduced from a 9-byte parent.
- `apply_scale` multiplies two signed int32 values. UndefinedBehaviorSanitizer reports `signed-integer-overflow` at `riftpacket.c:71`.

Invariants `data_before_auth` and `auth_without_open` are behavioral signals. On a normal exit they stay `SUSPICIOUS_DIVERGENCE`. The skeptic contradicts “this divergence is memory corruption” for those records.

## Reproduction

Confirmed findings store `replay_argv`: the `vrfuzz_riftpacket` binary, `replay`, `--input`, the minimized file, `--timeout-ms`. The dashboard re-runs that argv after the allowlist check and reports whether `exit_type`, sanitizer, and frame still match.

## What this document does not contain

No CVE ids, no CVSS, no exploit primitives, no “critical” ranking. If a future input shows only a novel state, the UI must keep the novel-behavior label.
