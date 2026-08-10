# Verify the evidence trail with any of the five SDKs

The committed evidence under `evidence/` is the claim. Everything below re-verifies it
offline against the published `v1.0.0-alpha.16` release of the Ratify protocol SDKs: no
call to either company, no trust in this repository's own code required.

Claim labels: `commit-1`, `commit-2`, `commit-3`, `killswitch`.

Each lane checks, per claim:

1. bundle: `identity_status` reproduces the recorded decision (`authorized_agent`, or
   `revoked` for the kill switch)
2. receipt: signature verifies against the verifier key
3. receipt: `bundle_hash` binding matches the hash of the committed bundle
4. receipt: `prev_hash` chain link is intact (genesis is 32 zero bytes)

The C lane covers checks 1 and 2 only; the current C FFI surface does not expose the two
binding accessors. Those checks are covered by the other four lanes over the same bytes.

## The head checkpoint

The four checks above are per claim. They catch a mutated receipt and a receipt deleted
from the middle, because both break a `prev_hash` link. They do not catch truncation of
the newest entries: a chain with its tail removed is still internally consistent, and the
manifest listing the claims would be trimmed to match.

`evidence/checkpoint.json` closes that. It binds the exact bytes of `evidence/manifest.json`,
the bytes of the final receipt, the ordered claim count, an evidence-set identifier and a
timestamp, signed by the verifier key. `npm run engagement` verifies it before checking any
claim, and the detection cases run on their own:

```
npm run checkpoint-test
```

**What the checkpoint is worth depends on where its signer comes from.** A checkpoint
carries its own signer's public key, so anyone able to rewrite the evidence can re-sign a
fresh checkpoint over the rewritten version and it will verify against itself. So
verification takes the expected signer as an argument and refuses a checkpoint signed by
anything else. For live evidence, the signed head must be published outside this repository
so the pinned value does not come from the artifact it attests. `checkpoint-test` covers
both halves: unpinned, a re-signed forgery verifies; pinned, it is refused.

Offline, the pinned signer is the deterministic demo verifier key, so the pin is circular
by construction. That is the correct property for a reproducible model, and it is the
reason the offline evidence set proves reproducibility rather than authenticity. The live
run will sign with a real deployment verifier key whose private half never enters this
repository, and its signed head will be published separately. Until both conditions are
satisfied, the live evidence must not be described as tamper-evident end to end.

## TypeScript (npm `@identities-ai/ratify-protocol`)

```
npm ci
npm run engagement                        # everything: scenes, replay, adversarial annex
npx tsx scripts/verify-one.ts commit-1    # one claim
```

## Go (module `github.com/identities-ai/ratify-protocol`)

```
cd verify/go
go run .              # all claims, in manifest order
go run . commit-1     # one claim
```

## Python (PyPI `ratify-protocol`)

```
cd verify/python
python3 -m venv .venv
./.venv/bin/pip install "ratify-protocol==1.0.0a16"
./.venv/bin/python verify_one.py              # all claims
./.venv/bin/python verify_one.py commit-1     # one claim
```

## Rust (crates.io `ratify-protocol`)

```
cd verify/rust
cargo run --release               # all claims
cargo run --release commit-1      # one claim
```

## C (built from the SDK source)

Clone `github.com/identities-ai/ratify-protocol` (tag `v1.0.0-alpha.16`) as a sibling of
this repository, build the C SDK (`cargo build --release` in `sdks/c`), then follow the
build command in the header of `verify/c/verify_one.c`.

## A note on determinism

Keys, IDs, scopes, constraints, challenges, timestamps, and decisions are all
deterministic (fixed demo seeds and a fixed time base). The ML-DSA-65 half of each hybrid
signature is hedged (randomized) by design, so regenerating the evidence
(`npm run evidence`) produces different signature bytes that still verify. Verification
is exact; generation is not byte-reproducible. That is a property of the signature
scheme, not of the claims.
