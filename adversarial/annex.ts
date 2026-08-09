/**
 * Adversarial annex: runnable FAILING tests a skeptic can run.
 *
 * Each case asserts a refusal, and each has a NEGATIVE CONTROL: it must fail loudly if its
 * protection is disabled, so a green run is evidence, not a vacuous pass. The refusal is a
 * deterministic Ratify error_reason / identity_status, except the federation case, whose refusal
 * is a deployment serve-authority policy decision layered on a valid verification.
 *
 * Cases 1 and 3-7 are buildable now against the published alpha.16 code (case 7 is the federation
 * serve-authority policy, offline). Cases 2 and 8 are gated on Agent Relay's confinement closure
 * (the OS-enforced filesystem boundary).
 */

import {
  MemoryChallengeStore,
  SCOPE_FILES_READ,
  SCOPE_FILES_WRITE,
  SCOPE_IDENTITY_DELEGATE,
  verifyBundle,
  type IdentityStatus,
} from "@identities-ai/ratify-protocol";

import {
  CLIENT_DEPLOYMENT_AUTHORITY,
  CONTRACTOR_DEPLOYMENT_AUTHORITY,
  SetRevocationProvider,
  T0,
  buildBundle,
  buildChain,
  buildVerificationContext,
  relayResourceId,
  servesAuthority,
  sessionContextFor,
} from "../src/harness.js";

type Case = {
  id: string;
  claim: string;
  expectedRefusal: string; // Ratify error_reason / identity_status, or the deployment-policy reason (federation)
  gated?: "confinement-closure";
};

export const CASES: Case[] = [
  { id: "escalation",   claim: "a child claims a scope the parent never held",
    expectedRefusal: "scope_denied" },
  { id: "path-traversal", claim: "a request for a path outside /docs (dot-segments, separator tricks)",
    expectedRefusal: "constraint_denied", gated: "confinement-closure" }, // logical denial now; real FS denial after closure
  { id: "replay",       claim: "a previously used bundle/challenge is re-presented",
    expectedRefusal: "invalid" }, // single-use challenge / freshness
  { id: "expired",      claim: "a cert past expires_at",
    expectedRefusal: "expired" },
  { id: "revoked",      claim: "the kill-switch case as a standalone test",
    expectedRefusal: "revoked" },
  { id: "wrong-operation", claim: "middleware attaches a valid proof to a different operation",
    expectedRefusal: "invalid" }, // operation-context binding mismatch
  { id: "federation", claim: "same channel id under a different deployment authority than the verifier serves",
    expectedRefusal: "unserved_authority" }, // deployment serve-authority policy; the delegation itself stays valid
  { id: "isolation-two-principal", claim: "an untrusted principal cannot mutate the root or hardlink the staging inode during a write",
    expectedRefusal: "OS-denied", gated: "confinement-closure" }, // Agent Relay deliverable; reference their executable proof
];

// For each case:
//   1. construct the adversarial input,
//   2. run it through verifyBundle / the adapter,
//   3. assert the refusal matches expectedRefusal,
//   4. NEGATIVE CONTROL: disable the specific protection and assert the case now PASSES-through
//      (proving the test actually exercises the protection).

const NOW = T0 + 60;
const PATH = "/docs/getting-started.md";

/** A case result: refused correctly AND its negative control passed through. */
interface Outcome {
  id: string;
  refused: boolean;      // protection ON produced the expected refusal
  controlOK: boolean;    // protection OFF let the same input through (genuine control)
  detail: string;
}

function refusalMatches(status: IdentityStatus, errorReason: string | undefined, expected: string): boolean {
  return status === expected || (errorReason ?? "").includes(expected);
}

// 1. Scope escalation: the leaf claims files:write the root never held.
async function caseEscalation(): Promise<Outcome> {
  const chain = await buildChain({ rootScope: [SCOPE_FILES_READ, SCOPE_IDENTITY_DELEGATE], leafScope: [SCOPE_FILES_WRITE], label: "escalation" });
  const bundle = await buildBundle(chain.implAgent, chain.implPriv, chain.delegations, seed("escalation"), NOW);
  const ctx = buildVerificationContext(PATH);

  // Protection ON: require files:write -> effective scope intersection is empty -> scope_denied.
  const on = await verifyBundle(bundle, { required_scope: SCOPE_FILES_WRITE, context: ctx, now: NOW });
  const refused = refusalMatches(on.identity_status, on.error_reason, "scope_denied");

  // Negative control: drop the required-scope check -> the identity itself still verifies.
  const off = await verifyBundle(bundle, { context: ctx, now: NOW });
  const controlOK = off.valid && off.identity_status === "authorized_agent";

  return { id: "escalation", refused, controlOK, detail: `on=${on.identity_status} off=${off.identity_status}` };
}

// 3. Replay: a consumed single-use challenge is re-presented (MemoryChallengeStore).
async function caseReplay(): Promise<Outcome> {
  const chain = await buildChain({ label: "replay" });
  const store = new MemoryChallengeStore();
  const issued = await store.issue(undefined, 300);
  const bundle = await buildBundle(chain.implAgent, chain.implPriv, chain.delegations, issued.challenge, NOW);
  const ctx = buildVerificationContext(PATH);

  // Protection ON: first presentation consumes the challenge, second is refused.
  const first = await verifyBundle(bundle, { required_scope: SCOPE_FILES_WRITE, context: ctx, challenge_store: store, now: NOW });
  const replayed = await verifyBundle(bundle, { required_scope: SCOPE_FILES_WRITE, context: ctx, challenge_store: store, now: NOW });
  const refused = first.valid && refusalMatches(replayed.identity_status, replayed.error_reason, "invalid");

  // Negative control: no single-use store -> the same bundle re-verifies within its freshness window.
  const off = await verifyBundle(bundle, { required_scope: SCOPE_FILES_WRITE, context: ctx, now: NOW });
  const controlOK = off.valid && off.identity_status === "authorized_agent";

  return { id: "replay", refused, controlOK, detail: `first=${first.identity_status} replay=${replayed.identity_status} off=${off.identity_status}` };
}

// 4. Expired authority: a cert past expires_at. (Temporal check precedes liveness in the verifier.)
async function caseExpired(): Promise<Outcome> {
  const expiresAt = T0 + 3600;
  const chain = await buildChain({ expiresAt, label: "expired" });
  // Challenge signed at issuance-time so the negative control has a fresh challenge.
  const bundle = await buildBundle(chain.implAgent, chain.implPriv, chain.delegations, seed("expired"), NOW);
  const ctx = buildVerificationContext(PATH);

  // Protection ON: verify well after expiry.
  const on = await verifyBundle(bundle, { required_scope: SCOPE_FILES_WRITE, context: ctx, now: expiresAt + 3600 });
  const refused = refusalMatches(on.identity_status, on.error_reason, "expired");

  // Negative control: verify within the validity window -> passes.
  const off = await verifyBundle(bundle, { required_scope: SCOPE_FILES_WRITE, context: ctx, now: NOW });
  const controlOK = off.valid && off.identity_status === "authorized_agent";

  return { id: "expired", refused, controlOK, detail: `on=${on.identity_status} off=${off.identity_status}` };
}

// 5. Revoked authority: the kill-switch as a standalone test.
async function caseRevoked(): Promise<Outcome> {
  const chain = await buildChain({ label: "revoked" });
  const bundle = await buildBundle(chain.implAgent, chain.implPriv, chain.delegations, seed("revoked"), NOW);
  const ctx = buildVerificationContext(PATH);

  // Protection ON: the root cert is on the revocation list.
  const revocation = new SetRevocationProvider(new Set([chain.rootCert.cert_id]));
  const on = await verifyBundle(bundle, { required_scope: SCOPE_FILES_WRITE, context: ctx, revocation, now: NOW });
  const refused = refusalMatches(on.identity_status, on.error_reason, "revoked");

  // Negative control: empty revocation list -> passes.
  const empty = new SetRevocationProvider(new Set());
  const off = await verifyBundle(bundle, { required_scope: SCOPE_FILES_WRITE, context: ctx, revocation: empty, now: NOW });
  const controlOK = off.valid && off.identity_status === "authorized_agent";

  return { id: "revoked", refused, controlOK, detail: `on=${on.identity_status} off=${off.identity_status}` };
}

// 6. Wrong-operation binding: a proof bound to operation A is presented for operation B.
async function caseWrongOperation(): Promise<Outcome> {
  const chain = await buildChain({ label: "wrong-op" });
  // The proof is cryptographically bound to operation A (session_context over its operation context).
  const scA = sessionContextFor(chain.implAgent.id, PATH, "git.commit:/docs/getting-started.md");
  const bundle = await buildBundle(chain.implAgent, chain.implPriv, chain.delegations, seed("wrong-op"), NOW, scA);
  const ctx = buildVerificationContext(PATH);

  // Protection ON: verifier reconstructs the session_context for a DIFFERENT operation B.
  const scB = sessionContextFor(chain.implAgent.id, "/docs/other.md", "git.commit:/docs/other.md");
  const on = await verifyBundle(bundle, { required_scope: SCOPE_FILES_WRITE, context: ctx, session_context: scB, now: NOW });
  const refused = refusalMatches(on.identity_status, on.error_reason, "invalid");

  // Negative control: verifier uses the operation the proof was actually bound to (A) -> passes.
  const off = await verifyBundle(bundle, { required_scope: SCOPE_FILES_WRITE, context: ctx, session_context: scA, now: NOW });
  const controlOK = off.valid && off.identity_status === "authorized_agent";

  return { id: "wrong-operation", refused, controlOK, detail: `on=${on.identity_status} off=${off.identity_status}` };
}

// 7. Federation: same-id-wrong-authority (the (a) two-deployment scene, article scene 3).
// A grant naming the SAME channel id under a DIFFERENT deployment authority than the verifier
// serves is refused by the serve-authority policy, even though the delegation is cryptographically
// valid. Cross-deployment authority is legitimate (FEDERATION-NAMESPACE-RULE §2). The refusal is
// the namespace rule §3: a verifier refuses a resource under an <authority> it does not serve.
//
// IMPORTANT: this refusal is NOT a Ratify identity_status. The SDK returns authorized_agent; the
// deployment/adapter refuses on its OWN serve-authority rule, with the policy reason
// `unserved_authority`. resource_id stays opaque to Ratify core; this is deployment policy, not a
// protocol change and not a value the verifier core emits.
async function caseFederation(): Promise<Outcome> {
  const SERVED = CLIENT_DEPLOYMENT_AUTHORITY; // the deployment this verifier authoritatively serves
  const CHANNEL_ID = "206880000000000456"; // one numeric channel id...
  const rightHost = relayResourceId(SERVED, "channel", CHANNEL_ID); // ...on the served host
  const wrongHost = relayResourceId(CONTRACTOR_DEPLOYMENT_AUTHORITY, "channel", CHANNEL_ID); // ...same id, other host

  // A grant over the same-id resource under the WRONG authority, cryptographically valid.
  // A channel is not path-scoped, so bind path_prefix "/" and verify at "/".
  const chain = await buildChain({ resourceId: wrongHost, pathPrefix: "/", label: "federation" });
  const bundle = await buildBundle(chain.implAgent, chain.implPriv, chain.delegations, seed("federation"), NOW);
  const ctx = buildVerificationContext("/", wrongHost);

  // The delegation itself verifies. The crypto does not (and must not) reject cross-deployment authority.
  const verify = await verifyBundle(bundle, { required_scope: SCOPE_FILES_WRITE, context: ctx, now: NOW });

  // The deployment-policy decision, expressed as the adapter's refusal reason (NOT a Ratify status):
  // empty string = accepted; "unserved_authority" = refused because the verifier does not serve
  // that resource's deployment authority.
  const policyReason = (rid: string, served: string): string =>
    servesAuthority(rid, served) ? "" : "unserved_authority";

  // Protection ON: this verifier serves SERVED, so it accepts the right-host id and refuses the same
  // id under the contractor authority with reason `unserved_authority`.
  const refused =
    verify.valid &&
    policyReason(rightHost, SERVED) === "" &&                  // correctly-hosted resource IS served
    policyReason(wrongHost, SERVED) === "unserved_authority";  // same id under the other authority is REFUSED

  // Negative control: a verifier that DOES serve the contractor authority accepts the very same
  // grant. Proves the refusal is the serve-authority policy, not the crypto and not a malformed id.
  const controlOK = verify.valid && policyReason(wrongHost, CONTRACTOR_DEPLOYMENT_AUTHORITY) === "";

  return {
    id: "federation",
    refused,
    controlOK,
    detail: `verify=${verify.identity_status} policy(right)=served policy(wrong-here)=${policyReason(wrongHost, SERVED) || "served"}`,
  };
}

function seed(label: string): Uint8Array {
  // Local deterministic 32-byte challenge (kept here so annex cases don't depend on committed inputs).
  const enc = new TextEncoder().encode(`annex-challenge:${label}`);
  const out = new Uint8Array(32);
  for (let i = 0; i < enc.length && i < 32; i++) out[i] = enc[i]!;
  // Pad the rest deterministically.
  for (let i = enc.length; i < 32; i++) out[i] = (i * 31 + 7) & 0xff;
  return out;
}

/** Run the annex. Returns refused/total over the runnable cases; gated cases are SKIPPED, never counted as passing. */
export async function runAnnex(): Promise<{ refused: number; total: number }> {
  const runnable = [caseEscalation, caseReplay, caseExpired, caseRevoked, caseWrongOperation, caseFederation];
  const outcomes: Outcome[] = [];
  for (const fn of runnable) outcomes.push(await fn());

  let refused = 0;
  for (const o of outcomes) {
    const pass = o.refused && o.controlOK;
    if (pass) refused++;
    console.log(
      `annex   ${o.id}: refusal=${o.refused ? "yes" : "NO"} negative-control=${o.controlOK ? "passes-through" : "DID-NOT-PASS"} -> ${pass ? "OK" : "FAIL"} (${o.detail})`,
    );
  }

  // Gated cases: SKIP loudly. They must NOT silently pass.
  for (const c of CASES.filter((c) => c.gated)) {
    console.log(`annex   ${c.id}: SKIP (runs against Agent Relay's OS-enforced confinement adapter in the live engagement, not in this offline harness)`);
  }

  return { refused, total: runnable.length };
}
