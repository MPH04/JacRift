# JacRift campaign fixture board

This Next.js app renders a synthetic riftpacket campaign from `../var/state.json`. It can start `jac run jac/main.jac` or an allowlisted replay of `vrfuzz_riftpacket` / `vrfuzz_hostile`.

It is a **TEST / DEMONSTRATION FIXTURE**. It does not accept a GitHub repository and it does not classify findings.

The repository analysis product is the Jac app:

```bash
jac start main.jac --port 8000
```

Run this board only when you are inspecting the local fuzzer campaign:

```bash
npm install
npx next dev -p 43117 -H 0.0.0.0
```
