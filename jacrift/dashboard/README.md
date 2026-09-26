# VectorRift dashboard

Next.js board for a campaign published by the Jac runtime. It reads `../var/state.json` and can start `jac run` or an allowlisted replay. It does not classify findings.

```bash
npm install
npx next dev -p 43117 -H 0.0.0.0
```

The repo README covers the threat model, the evidence ladder, and how to build the native target first.
