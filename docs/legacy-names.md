# Legacy names

The public product name is **JacRift**.

These identifiers stay because renaming them would break the synthetic campaign, the native binaries, or saved event files. They are not a second product.

| Name | Where it still appears | Why it remains |
| --- | --- | --- |
| `vectorrift.execution.v1` | Event lines from `native/` and `jac/schema.jac` | On-disk schema. `jacrift.execution.v1` is accepted and stored as `vectorrift.execution.v1`. |
| `vectorrift.state.v1` | `var/state.json` for a riftpacket campaign | Campaign publish format. `jrlib/compat.py` loads it as `jacrift.state.v2` with `compat_from`. |
| `vectorrift.minimize.v1` | Minimizer output for the C engine | Campaign-only. Repository jobs store minimizers on the finding reproducer. |
| `vrfuzz_riftpacket`, `vrfuzz_hostile` | `native/build/` | Binary allowlist in the campaign dashboard. |
| `VectorRift` | Historical docs and comments inside the campaign modules | The campaign report heading is now JacRift and says the file is the synthetic riftpacket campaign. |

Repository jobs use `jacrift.job.v1` in `state.json`. They do not write `vectorrift.state.v1`.

The nested `jacrift/` directory that duplicated this repository has been removed. The modules at the repository root are the only copy.
