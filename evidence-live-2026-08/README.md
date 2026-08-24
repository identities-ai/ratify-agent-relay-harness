# Live-run evidence, August 2026

This directory holds artifacts from the two live sessions of 18 and 19 August 2026. It is
**not** the same thing as `evidence/`, which is a synthetic model with fixture identifiers,
built so that this repository runs on a laptop with neither deployment present.

Use `evidence/` to check whether the mechanism behaves as described. Use this directory to
check what happened on those two days.

## What is here

`client/` holds the artifacts the client produced and signed. Every delegation certificate
issued during the engagement, the signed revocation and the envelope that carried it, the
client deployment's own logs across the run window, and the timestamp capture.

Everything in `client/` is public material: public keys, signed certificates, revocation
lists and log output. No private key, token or credential appears in any of it.

## What is not here yet

The contractor's half. Agent Relay's receipts, deployment decisions, child certificates and
adapter metadata are theirs to release, and they publish on their side. A reader checking the
crossing needs both halves, and this one on its own evidences only what the client sent and
when.

## Reading the revocation

`revocation-live-0819.json` is the signed list, which is the evidence to keep.
`revocation-live-0819-envelope.json` is what actually travelled. The plain list verifies
against the client root `345140967b9b99a16983cdfeb8acc807`; the envelope is what the
contractor's deployment received and applied at 18:02:11.123Z.

The certificate it revokes, `relay-run-1787160460`, is in `2026-08-19/delegation-live-0819.json`
and carried validity until 21:27:40Z, so the refusal that followed cannot be read as expiry.
