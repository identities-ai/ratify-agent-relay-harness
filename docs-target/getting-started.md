# Getting started

This example runs a tiny "verify before serve" flow: a caller presents a delegated-authority proof, the service verifies it, and only then performs the requested write. An invalid, expired, or out-of-scope proof is refused with a clear reason and no side effect.

## Run it

1. Install the dependencies (see [Install](./guides/install.md)).
2. Start the example verifier.
3. Send a request with a valid proof scoped to the target path. The write is accepted and a receipt is returned.
4. Send the same request with a tampered, expired, or wrong-path proof. The service refuses, fail-closed, and names the reason.

## What to look at

- The verify step happens before any side effect. Nothing is written until the proof checks out.
- The refusal path returns a stable reason such as `expired`, `scope_denied`, or `revoked`, rather than a generic error.
- The authority is bound to a specific path. A proof valid for one path does not authorize a write to another.

## Next

- [Install](./guides/install.md) for setup details.
- The refusal cases are the interesting part. Try breaking the proof and watch each one fail closed.
