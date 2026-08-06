# Example: verify before serve

A minimal reference showing a service that verifies a delegated-authority proof before it does any work. It is intentionally small: one accept path, one refusal path, no framework.

This repository is a purpose-built example for the Agent Relay x Ratify Phase 2 engagement. It is not production software and holds nothing sensitive.

## Contents

- [Getting started](./getting-started.md): run the example end to end in a few minutes.
- [Install](./guides/install.md): dependencies and setup.

## What it demonstrates

- A verifier performs an operation only when the presented authority verifies, and refuses otherwise, fail-closed.
- The authority names both what may be done and where, so a valid proof for one path does not authorize another.
- Every accepted operation produces a signed receipt that anyone can check later, offline.
