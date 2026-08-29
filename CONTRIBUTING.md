# Contributing

- The approved UI is `prototype/portal.html`. Match it; if behaviour is unclear,
  that file is the answer.
- The design and its reasoning live in `docs/ARCHITECTURE.md`. Read the relevant
  section before changing a subsystem.
- **Never commit secrets.** Use `.env` (git-ignored); document new keys in
  `.env.example`.
- Every SOC figure is computed by a deterministic tool, never by the model.
- Every query is tenant-scoped server-side. Do not trust caller-supplied tenants.
