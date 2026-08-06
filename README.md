# Agent Relay × Ratify — Phase 2 engagement (reproduction repo)

**Status:** the non-gated half runs end to end offline (`npm run engagement`, exit 0). This is the Identities-AI-side reproduction harness and adversarial annex for the Phase 2 flagship. It orchestrates and publishes an engagement that runs on Agent Relay's adapter + confinement; it does not reimplement them. The path-traversal and two-principal-isolation cases stay gated on the partner confinement closure.

Ratify is infrastructure here: it supplies the portable delegated-authority proof. Agent Relay coordinates the work and enforces the filesystem boundary.

## What this repo is
- The one-command reproduction of the engagement (`npm run engagement`), offline, exits non-zero if any published claim fails to re-verify.
- The published evidence trail: the delegation chain, every `ProofBundle`, and the `VerificationReceipt` chain, committed under `evidence/`.
- The adversarial annex (`adversarial/`): runnable failing tests a skeptic can run.

## What this repo is not
- Not the target repo. The delegation is bound to `/docs` of a separate public repo, `identities-ai/<engagement-repo>`.
- Not the adapter or confinement layer. Those are Agent Relay's (`@relayfile/local-mount`, `@relaycast/engine`, and the confinement work in their `ratify-demo`).

## One-command flow
```
npm ci
npm run engagement    # replays the engagement scenes (delegation, handoff, the federation beat, the work +
                      # receipts, the kill switch), writes evidence/, re-verifies every bundle + receipt
                      # offline, runs the adversarial annex, prints: "engagement: N/N verified, M/M refused"
npm run typecheck     # tsc --noEmit
```
Offline by default. No call to either company. A reader reproduces every claim with the open SDKs.
The local dev build depends on the workspace SDK via a `file:` dependency (`@identities-ai/ratify-protocol`); the published reproduction pins the alpha.16 tag once cut.

Determinism: keys, IDs, scopes, constraints, challenges, timestamps and decisions are deterministic (fixed demo seeds + a fixed time base). The ML-DSA-65 half of each hybrid signature is *hedged* by the pinned `@noble/post-quantum`, so raw signature bytes differ between generations while every signature still verifies — see `evidence/VERIFY.md`.

## Verify with any of the five SDKs (the point of the exercise)
The evidence trail is SDK-agnostic. Each published bundle/receipt can be re-verified with Go, TypeScript, Python, Rust, or C. The TypeScript commands run as-is (`npx tsx scripts/verify-one.ts commit-1`); the other four are templated with the correct invocation shape. See `evidence/VERIFY.md`.

## Dependencies and what is gated
- **Buildable now (offline, on `main`):** the full five-scene harness, the evidence-trail format + replay, and adversarial cases for scope escalation, replay, expired, revoked, wrong-operation binding, and the federation same-id-wrong-authority refusal — each with a genuine negative control (resource_path, receipts, operation-context, and the deployment serve-authority policy are all in place). The federation case models scene 3 of the (a) two-deployment scope: a grant naming the same channel id under a deployment authority the verifier does not serve is refused by policy, while the delegation itself verifies (authority-to-act and resource-namespace are orthogonal — see `../../to-relay/FEDERATION-NAMESPACE-RULE-2026-08-04.md`).
- **Gated on the alpha.16 tag** (held on Agent Relay's confinement closure): pinned installable alpha.16 SDK builds, and the fully-enforced path-traversal + two-principal isolation cases (they SKIP loudly here, never silently pass).

## Layout
- `src/engagement.ts` — the five-scene harness.
- `src/harness.ts` — shared offline/deterministic primitives (demo keys, chain builder, contexts, revocation provider).
- `adversarial/annex.ts` — the runnable failing tests + negative controls + case list.
- `scripts/verify-one.ts` — re-verify a single published claim from the committed bytes.
- `evidence/` — bundles, receipts, delegation chain, `manifest.json`, and `VERIFY.md`.
- `docs-target/` — a mirror of the `/docs` content the agent works in (for local rehearsal before the real repo exists).

See `../../publications/phase2-flagship/repo-and-harness-SPEC.md` for the full spec and `../../publications/phase2-flagship/article-DRAFT.md` for the article this run feeds.
