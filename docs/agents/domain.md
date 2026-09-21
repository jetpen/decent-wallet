# Domain Docs

How the engineering skills should consume this repo's domain documentation.

## Before exploring, read these

- **`CONTEXT.md`** at the repo root.
- **`docs/adr/`**: read ADRs that touch the area you're about to work in.

If any of these files don't exist, proceed silently. Don't flag their absence or suggest creating them upfront. Create them lazily when terms or decisions actually get resolved.

## File structure

This is a single-context repository:

```
/
├── CONTEXT.md
├── docs/adr/
│   ├── 0001-event-sourced-orders.md
│   └── 0002-postgres-for-write-model.md
└── src/
```

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor proposal, a hypothesis, or a test name), use the term as defined in `CONTEXT.md`. If the concept you need isn't in the glossary yet, note it as a signal for domain modeling.

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather than silently overriding:

> _Contradicts ADR-0007, but worth reopening because…_
