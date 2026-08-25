# Agent Relay × Ratify: Phase 2 engagement (reproduction repo)

On 18 and 19 August 2026, one company's digital workers did real work in another company's
repository, under authority that was granted narrowly, narrowed again when it was passed on,
and revoked while the work was still running. This repository replays that offline so you can
check it rather than take it.

```
npm ci && npm run engagement
```

A clean run prints `engagement: 8/8 verified, 6/6 refused`, and exits non-zero if any
published claim fails to re-verify. No network call to either company.

**What Ratify is.** An open protocol for delegated authority that is bounded to a named
resource, revocable while work is in flight, and verifiable offline by the party receiving
it. The receiving side checks who authorized what, for how long, and whether it still stands,
without calling the party that issued it.

| | |
|---|---|
| Protocol and spec | [identities-ai/ratify-protocol](https://github.com/identities-ai/ratify-protocol) |
| SDKs, five languages | [sdks/](https://github.com/identities-ai/ratify-protocol/tree/main/sdks) |
| How to verify by hand | [VERIFY.md](VERIFY.md) |
| Live evidence, client half | [`evidence-live-2026-08/client/`](evidence-live-2026-08/client) |
| Live evidence, contractor half | [AgentWorkforce/ratify-agent-relay-evidence](https://github.com/AgentWorkforce/ratify-agent-relay-evidence) |
| Agent Relay's account of the run | [Someone else's agent in your repo](https://agentrelay.com/blog/someone-elses-agent-in-your-repo) |
| The full engagement record | [Phase 2 technical note](https://ratifyprotocol.com/writing/agent-relay-phase2-technical-note) |

This is the Ratify-Protocol-side reproduction harness and adversarial annex. It orchestrates
an engagement that runs on [Agent Relay](https://agentrelay.com)'s adapter and confinement; it
does not reimplement them. The path-traversal and two-principal-isolation cases need two OS
principals with distinct uids inside that confinement boundary, and the adapter runs as a
single unprivileged uid, so they SKIP here and the annex reads six refusals rather than eight.
The write-up says why rather than quietly reporting eight.

If any of this is useful, star the repository, and tell us which authority boundary you would
want tested next.

## What this repo is
- The one-command reproduction of the engagement (`npm run engagement`), offline, exits non-zero if any published claim fails to re-verify.
- The published evidence trail for that offline run: the delegation chain, every `ProofBundle`, the `VerificationReceipt` chain, and a verifier-signed head checkpoint committed under `evidence/`.
- The adversarial annex (`adversarial/`): runnable failing tests a skeptic can run.

## The offline model and the live run are different things

Everything under `evidence/` is a **synthetic model** of the engagement, built so that someone with neither deployment can run it. Its identifiers are fixtures: `demo-cert-root`, a demo channel id, fixed timestamps. Nothing in here is a certificate that was issued during the live sessions of 18 and 19 August 2026.

That is deliberate. This repository answers "does the mechanism behave as described", offline and on any machine. It does not, on its own, evidence that a particular thing happened on a particular day.

Two consequences worth stating plainly:

- **The head checkpoint exists here and did not exist in the live run.** The offline model produces one, and `npm run checkpoint-test` exercises truncation detection against it. The live engagement produced no signed head. Do not read the checkpoint in `evidence/` as an artifact of those sessions.
- **The live run's certificates, receipts, deployment decisions and logs are published separately.** The client's half is in this repository under `evidence-live-2026-08/client/`. Agent Relay publishes theirs at [`AgentWorkforce/ratify-agent-relay-evidence`](https://github.com/AgentWorkforce/ratify-agent-relay-evidence). Checking the crossing needs both halves; either alone evidences only what its own side did.

## What this repo is not
- Not the target repo. The delegation is bound to `/docs` of a separate public repo, `identities-ai/ratify-agent-relay-engagement`.
- Not the adapter or confinement layer. Those are Agent Relay's (`@relayfile/local-mount`, `@relaycast/engine`, and their OS-enforced confinement adapter).

## One-command flow
```
npm ci
npm run engagement    # replays the engagement scenes (delegation, handoff, the federation beat, the work +
                      # receipts, the kill switch), re-verifies every committed bundle + receipt offline,
                      # runs the adversarial annex, prints: "engagement: N/N verified, M/M refused".
                      # Never modifies evidence/, so a verification run leaves the clone clean.
npm run evidence      # same run, but regenerates evidence/ first (--write-evidence). Signature bytes
                      # differ on every regeneration (hedged ML-DSA); commit the result deliberately.
npm run typecheck     # tsc --noEmit
```
Offline by default. No call to either company. A reader reproduces every claim with the open SDKs.
All dependencies pin the published `v1.0.0-alpha.17` release: npm `@identities-ai/ratify-protocol`, the Go module tag, crates.io `ratify-protocol`, and PyPI `ratify-protocol==1.0.0a17`.

Determinism: keys, IDs, scopes, constraints, challenges, timestamps and decisions are deterministic (fixed demo seeds + a fixed time base). The ML-DSA-65 half of each hybrid signature is *hedged* by the pinned `@noble/post-quantum`, so raw signature bytes differ between generations while every signature still verifies. See `VERIFY.md`.

## Verify with any of the five SDKs (the point of the exercise)
The evidence trail is SDK-agnostic. Each published bundle/receipt can be re-verified with Go, TypeScript, Python, Rust, or C, and the first four run as committed against the published SDK releases. The C lane builds from a source checkout of the SDK. See `VERIFY.md` for every command.

## Dependencies and what is gated
- **Runs now (offline, on `main`):** the full engagement harness, the evidence-trail format + replay, and adversarial cases for scope escalation, replay, expired, revoked, wrong-operation binding, and the federation same-id-wrong-authority refusal, each with a genuine negative control (resource_path, receipts, operation-context, and the deployment serve-authority policy are all in place). The federation case models the two-deployment scene: a grant naming the same channel id under a deployment authority the verifier does not serve is refused by deployment policy (reason `unserved_authority`), while the delegation itself stays cryptographically valid. Authority-to-act and resource-namespace are orthogonal; a verifier serves exactly its own deployment authority and refuses resources under any other.
- **Enforced by Agent Relay's runtime, not this offline harness:** the fully-enforced path-traversal and two-principal isolation cases run against Agent Relay's OS-level confinement adapter in the real engagement; they SKIP loudly here, never silently pass.

## Layout
- `src/engagement.ts`: the engagement harness (delegation, handoff, federation, work + receipts, kill switch).
- `src/harness.ts`: shared offline/deterministic primitives (demo keys, chain builder, contexts, revocation provider).
- `adversarial/annex.ts`: the runnable failing tests + negative controls + case list.
- `scripts/verify-one.ts`: re-verify a single published claim from the committed bytes.
- `evidence/`: bundles, receipts, delegation chain, and `manifest.json`.
- `verify/`: the Go, Python, Rust, and C verifier lanes (see `VERIFY.md`).
- `docs-target/`: a mirror of the `/docs` content the agent works in (for local rehearsal before the engagement runs).

The engagement article links here when it publishes.
