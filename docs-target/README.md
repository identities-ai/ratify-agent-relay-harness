# docs-target: rehearsal mirror of the engagement's /docs

This directory mirrors the `/docs` tree of the public target repository (`identities-ai/<engagement-repo>`) that the Phase 2 engagement runs against, so the harness can rehearse locally before that repo exists.

During the engagement, the Agent Relay implementation agent, holding authority bound to `/docs` via a `resource_path` constraint, edits these files. It writes `getting-started.md`, adds `guides/install.md`, and updates `index.md` (see `src/engagement.ts`, the three commits). Each write is accepted only under valid, unexpired, unrevoked authority scoped to `/docs`, and every commit carries a verifier-signed receipt.

The content here is a purpose-built example. It is not production documentation and holds nothing sensitive. It represents the starting state of `/docs`; the engagement's commits are realistic edits on top of it.
