/**
 * Phase 2 engagement harness.
 *
 * Replays the engagement scenes (delegation, handoff, the offline federation model, the work
 * with receipts, and the kill switch) and re-verifies every published claim offline. This
 * is the Identities-AI-side orchestration; the Relay adapter + confinement are
 * the partner's (imported, not reimplemented). Points that depend on the Relay
 * adapter carrying the bundle, or on the OS-enforced filesystem boundary, are
 * marked TODO(adapter) where that layer genuinely belongs.
 *
 * Ratify supplies the portable proof. The execution environment supplies the
 * filesystem boundary.
 */

import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  SCOPE_FILES_WRITE,
  bundleHash,
  decodeProofBundle,
  decodeVerificationReceipt,
  encodeDelegationCert,
  encodeProofBundle,
  encodeVerificationReceipt,
  issueVerificationReceipt,
  receiptHash,
  verifyBundle,
  verifyVerificationReceipt,
  type DelegationCert,
  type IdentityStatus,
  type ProofBundle,
  type VerificationReceipt,
} from "@identities-ai/ratify-protocol";

import {
  CLIENT_DEPLOYMENT_AUTHORITY,
  CONTRACTOR_DEPLOYMENT_AUTHORITY,
  SetRevocationProvider,
  TARGET_RESOURCE_ID,
  VERIFIER_ID,
  buildBundle,
  buildChain,
  buildVerificationContext,
  demoKeypair,
  deterministicChallenge,
  parseRelayResourceId,
  relayResourceId,
  servesAuthority,
  syntheticSha,
  type Chain,
} from "./harness.js";
import { runAnnex } from "../adversarial/annex.js";

const EVIDENCE_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "evidence");

// One published engagement claim: a bundle, its verifier-signed receipt, and
// the metadata a reader needs to reproduce the exact verification.
interface Claim {
  label: string;
  sha: string;
  requestedPath: string;
  verifiedAt: number;
  expectedDecision: IdentityStatus;
  /** When true, the verifier applies the revocation list at replay. */
  revoked: boolean;
  bundle: ProofBundle;
  receipt: VerificationReceipt;
}

// The three files the implementation agent writes under /docs during the work.
const COMMITS = [
  { label: "commit-1", requestedPath: "/docs/getting-started.md" },
  { label: "commit-2", requestedPath: "/docs/guides/install.md" },
  { label: "commit-3", requestedPath: "/docs/index.md" },
] as const;

// ---------------------------------------------------------------------------
// Scenes
// ---------------------------------------------------------------------------

async function scene1_delegation(): Promise<Chain> {
  // Client (Identities AI) issues: scope files:write, resource_path { TARGET_RESOURCE_ID, /docs },
  // short expiry, revocable. Signed with the client root key. identity:delegate is granted on the
  // ROOT cert too; without it the sub-delegation in scene 2 fails closed (delegation_not_authorized);
  // the leaf narrows it away so the implementation agent cannot re-delegate.
  const chain = await buildChain();
  const r = await verifyBundle(
    await bundleFor(chain, "scene1-probe", "/docs/getting-started.md"),
    { required_scope: SCOPE_FILES_WRITE, context: buildVerificationContext("/docs/getting-started.md"), now: verifyAt(0) },
  );
  assert(r.valid && r.identity_status === "authorized_agent", `scene1 delegation should verify, got ${r.identity_status}: ${r.error_reason}`);
  console.log(`scene1  delegation issued: scope=[files:write] resource_path={${TARGET_RESOURCE_ID}, /docs} (revocable, expires_at short)`);
  return chain;
}

async function scene2_handoff(chain: Chain): Promise<void> {
  // Lead agent sub-delegates to the implementation agent; authority narrows at the hop (the leaf
  // cert drops identity:delegate). There is no real Relay middleware here; buildChain() models the
  // sub-delegation directly with the SDK.
  // TODO(adapter): in the real engagement the Relay middleware carries this bundle between agents
  //   (never the keys), mapping its grammar relayfile:fs:write:/docs/** to files:write +
  //   resource_path{repo, /docs}. That transport is Agent Relay's deliverable, not Ratify's.
  const leaf = chain.leafCert;
  assert(leaf.scope.includes(SCOPE_FILES_WRITE), "leaf must retain files:write");
  assert(!leaf.scope.includes("identity:delegate"), "leaf must NOT retain identity:delegate (narrowing at the hop)");
  console.log(`scene2  handoff: authority narrowed at the hop -> leaf scope=[${leaf.scope.join(", ")}]`);
}

function sceneParserBoundaries(): void {
  // Boundary vectors for the harness's Relay resource_id parser, taken from the live v0.6
  // profile (§4.0 per-type grammars, §7.1 canonical forms, §7.6 invalid inputs, §7.7 u64
  // bound). servesAuthority() fails closed on a parse failure, so the parser rejecting a
  // VALID id would silently refuse a legitimate grant — the accept vectors guard that.
  const ACCEPT = [
    "relay:v1:cast.agentrelay.com:workspace:206880000000000123",
    "relay:v1:cast.agentrelay.com:channel:206880000000000456",
    "relay:v1:cast.agentrelay.com:dm:206880000000000789", // group DM = Snowflake (§4.0)
    "relay:v1:cast.agentrelay.com:dm:dm_15c60360330ea3d22ae818a6", // 1:1 DM digest
    "relay:v1:cast.agentrelay.com:node:206880000000000999",
    "relay:v1:cast.agentrelay.com:node:node_direct_206880000000000111", // implicit node (§4.4)
    "relay:v1:relay.example.com:8443:channel:206880000000000456", // non-default port, 6 segments
    "relay:v1:cast.agentrelay.com:channel:18446744073709551615", // u64 max (§7.7)
    "relay:v1:cast.agentrelay.com:node:node_direct_18446744073709551615", // embedded u64 max
  ];
  const REJECT = [
    "relay:v1:cast.agentrelay.com:channel:18446744073709551616", // u64 max + 1
    "relay:v1:cast.agentrelay.com:channel:99999999999999999999", // 20 digits, above max
    "relay:v1:cast.agentrelay.com:channel:118446744073709551615", // 21 digits
    "relay:v1:cast.agentrelay.com:channel:04560", // leading zero
    "relay:v1:cast.agentrelay.com:channel:45x6", // non-digit
    "relay:v1:cast.agentrelay.com:node:node_direct_0123", // leading zero inside node_direct_
    "relay:v1:cast.agentrelay.com:node:node_direct_18446744073709551616", // embedded above max
    "relay:v1:cast.agentrelay.com:node:node_direct_", // empty embedded Snowflake
    "relay:v1:cast.agentrelay.com:workspace:dm_15c60360330ea3d22ae818a6", // digest under wrong type
    "relay:v1:cast.agentrelay.com:workspace:node_direct_206880000000000111", // implicit node under wrong type
    "relay:v1:cast.agentrelay.com:channel:node_direct_206880000000000111",
    "relay:v1:cast.agentrelay.com:dm:node_direct_206880000000000111",
    "relay:v1:cast.agentrelay.com:dm:DM_15c60360330ea3d22ae818a6", // uppercase prefix
    "relay:v1:cast.agentrelay.com:dm:dm_15C60360330EA3D22AE818A6", // uppercase digest
    "relay:v1:cast.agentrelay.com:dm:dm_15c60360330ea3d2", // wrong digest length
    "relay:v1:cast.agentrelay.com:node-pool:206880000000000999", // withdrawn type (§4.5)
    "relay:v1:cast.agentrelay.com:room:456", // type not in the enum
  ];

  for (const rid of ACCEPT) {
    const parsed = parseRelayResourceId(rid);
    assert(parsed !== null, `parser must accept valid v0.6 id: ${rid}`);
    // Round-trip stability (§7): reconstructing from the parsed components reproduces the bytes.
    assert(
      relayResourceId(parsed.authority, parsed.type, parsed.id) === rid,
      `parser round-trip must be byte-identical: ${rid}`,
    );
  }
  for (const rid of REJECT) {
    assert(parseRelayResourceId(rid) === null, `parser must reject invalid id: ${rid}`);
  }
  console.log(`scene-fed  parser boundaries: ${ACCEPT.length} valid accepted (round-trip stable), ${REJECT.length} invalid rejected`);
}

async function sceneFederation(): Promise<void> {
  // Article scene 3 (the (a) two-deployment federation beat), modeled offline and deterministically.
  // The coordination channel is a Relay resource whose identity is anchored to its deployment
  // authority: relay:v1:<host>:channel:<id>. Authority under the host THIS verifier serves is
  // accepted; the SAME channel id under a different deployment authority is refused by the
  // serve-authority policy, while the delegation itself stays cryptographically valid (authority-
  // to-act and resource-namespace are orthogonal; see FEDERATION-NAMESPACE-RULE-2026-08-04.md §3).
  // TODO(adapter): the real scene runs two independent Relay deployments federating over A2A; that
  //   transport and the second deployment are Agent Relay's deliverable. Here we model only the
  //   accept/refuse decision. The full adversarial form (with negative control) is the annex
  //   `federation` case, which also runs under this one command.
  const CHANNEL_ID = "206880000000000456";
  const served = CLIENT_DEPLOYMENT_AUTHORITY;
  const accepted = relayResourceId(served, "channel", CHANNEL_ID);
  const wrongAuthority = relayResourceId(CONTRACTOR_DEPLOYMENT_AUTHORITY, "channel", CHANNEL_ID);

  // The accepted grant: valid delegation AND a resource this verifier serves.
  const acceptChain = await buildChain({ resourceId: accepted, pathPrefix: "/", label: "fed-accept" });
  const acceptVerify = await verifyBundle(
    await buildBundle(acceptChain.implAgent, acceptChain.implPriv, acceptChain.delegations, deterministicChallenge("fed-accept"), verifyAt(0)),
    { required_scope: SCOPE_FILES_WRITE, context: buildVerificationContext("/", accepted), now: verifyAt(0) },
  );
  assert(
    acceptVerify.valid && acceptVerify.identity_status === "authorized_agent" && servesAuthority(accepted, served),
    `federation accept: should verify and be served, got ${acceptVerify.identity_status}: ${acceptVerify.error_reason}`,
  );

  // The same channel id under the contractor authority: refused here, because this verifier does
  // not serve that deployment. (Its delegation would still verify; it just names another namespace.)
  assert(
    !servesAuthority(wrongAuthority, served),
    "federation refuse: same channel id under a different deployment authority MUST be refused by this verifier",
  );

  console.log(
    `scene-fed  channel ${CHANNEL_ID}: accepted under ${served}; same id under ${CONTRACTOR_DEPLOYMENT_AUTHORITY} refused (unserved authority), delegation itself still valid`,
  );
}

async function scene3_work_with_receipts(chain: Chain): Promise<Claim[]> {
  // Implementation agent writes under /docs and commits. Each commit: verify-before-action, then a
  // verifier-signed VerificationReceipt binding bundle hash + outcome + time, chained by prev_hash.
  // TODO(adapter): the consequential filesystem write is mediated by the Relay adapter INSIDE the
  //   OS-enforced confinement boundary before it becomes observable. Here we only produce the proof
  //   and the receipt; the enforced write is Agent Relay's confinement deliverable.
  const claims: Claim[] = [];
  let prev: Uint8Array | null = null;
  for (let i = 0; i < COMMITS.length; i++) {
    const c = COMMITS[i]!;
    const now = verifyAt(i);
    const bundle = await bundleFor(chain, c.label, c.requestedPath, now);
    const result = await verifyBundle(bundle, {
      required_scope: SCOPE_FILES_WRITE,
      context: buildVerificationContext(c.requestedPath),
      now,
    });
    if (!result.valid) throw new Error(`scene3 ${c.label} refused (fail closed): ${result.error_reason}`);
    const receipt = await issueReceipt(bundle, result, prev, now);
    prev = receiptHash(receipt);
    claims.push({
      label: c.label,
      sha: syntheticSha(c.label),
      requestedPath: c.requestedPath,
      verifiedAt: now,
      expectedDecision: result.identity_status,
      revoked: false,
      bundle,
      receipt,
    });
    console.log(`scene3  ${c.label} ${syntheticSha(c.label).slice(0, 12)} ${c.requestedPath} -> ${result.identity_status}, receipt issued`);
  }
  return claims;
}

async function scene4_kill_switch(chain: Chain, prevClaims: Claim[]): Promise<Claim> {
  // Client revokes the upstream (root) delegation mid-task. The next handoff verifies as `revoked`
  // and fails closed. Capture the timestamp and the failed result for the article/video.
  const revokedSet = new Set([chain.rootCert.cert_id]);
  const revocation = new SetRevocationProvider(revokedSet);
  const now = verifyAt(prevClaims.length);
  const requestedPath = "/docs/after-revocation.md";
  const bundle = await bundleFor(chain, "killswitch", requestedPath, now);
  const result = await verifyBundle(bundle, {
    required_scope: SCOPE_FILES_WRITE,
    context: buildVerificationContext(requestedPath),
    revocation,
    now,
  });
  assert(!result.valid && result.identity_status === "revoked", `kill switch should return revoked, got ${result.identity_status}: ${result.error_reason}`);
  const prev = prevClaims.length ? receiptHash(prevClaims[prevClaims.length - 1]!.receipt) : null;
  const receipt = await issueReceipt(bundle, result, prev, now);
  console.log(`scene4  kill switch: root cert ${chain.rootCert.cert_id} revoked at t=${now} -> next handoff ${result.identity_status} (fail closed)`);
  return {
    label: "killswitch",
    sha: syntheticSha("killswitch"),
    requestedPath,
    verifiedAt: now,
    expectedDecision: "revoked",
    revoked: true,
    bundle,
    receipt,
  };
}

async function scene5_publish_and_reverify(chain: Chain, claims: Claim[]): Promise<{ verified: number; total: number }> {
  // Write the evidence trail (delegation chain, every ProofBundle, the VerificationReceipt chain)
  // under evidence/, then replay: re-verify every bundle and receipt offline, print each
  // identity_status, check the prev_hash chain is intact. Exits non-zero on any failure.
  await writeEvidence(chain, claims);

  // --- Offline replay: read committed inputs back from disk and re-verify. ---
  const manifest = JSON.parse(await readFile(join(EVIDENCE_DIR, "manifest.json"), "utf8")) as ManifestFile;
  const revoked = new Set(manifest.revoked_certs);
  const revocation = new SetRevocationProvider(revoked);

  let verified = 0;
  let total = 0;
  let prevReceiptHash: Uint8Array | null = null;
  const zero32 = new Uint8Array(32);

  for (const entry of manifest.claims) {
    const bundle = decodeProofBundle(await readFile(join(EVIDENCE_DIR, "bundles", `${entry.label}.json`), "utf8"));
    const receipt = decodeVerificationReceipt(await readFile(join(EVIDENCE_DIR, "receipts", `${entry.label}.json`), "utf8"));

    // (1) Re-verify the bundle; its status must reproduce the recorded decision.
    total++;
    const res = await verifyBundle(bundle, {
      required_scope: SCOPE_FILES_WRITE,
      context: buildVerificationContext(entry.requested_path),
      now: entry.verified_at,
      ...(entry.revoked ? { revocation } : {}),
    });
    const bundleOk = res.identity_status === entry.expected_decision;
    if (bundleOk) verified++;
    console.log(`replay  ${entry.label}: identity_status=${res.identity_status} (recorded ${entry.expected_decision}) ${bundleOk ? "OK" : "MISMATCH"}`);

    // (2) Re-verify the receipt: signature, bundle-hash binding, and prev_hash chain link.
    total++;
    const sigErr = await verifyVerificationReceipt(receipt);
    const hashOk = bytesEqual(receipt.bundle_hash, bundleHash(bundle));
    const expectedPrev = prevReceiptHash ?? zero32;
    const chainOk = bytesEqual(receipt.prev_hash, expectedPrev);
    const receiptOk = sigErr === null && hashOk && chainOk;
    if (receiptOk) verified++;
    console.log(`replay  ${entry.label}: receipt sig=${sigErr === null ? "ok" : "BAD"} bundle_hash=${hashOk ? "ok" : "BAD"} prev_hash_chain=${chainOk ? "ok" : "BROKEN"} ${receiptOk ? "OK" : "FAIL"}`);
    prevReceiptHash = receiptHash(receipt);
  }
  return { verified, total };
}

// ---------------------------------------------------------------------------
// Evidence trail I/O
// ---------------------------------------------------------------------------

interface ManifestClaim {
  label: string;
  sha: string;
  requested_path: string;
  verified_at: number;
  expected_decision: IdentityStatus;
  revoked: boolean;
}
interface ManifestFile {
  target_resource_id: string;
  bound_path_prefix: string;
  verifier_id: string;
  revoked_certs: string[];
  claims: ManifestClaim[];
}

async function writeEvidence(chain: Chain, claims: Claim[]): Promise<void> {
  await rm(EVIDENCE_DIR, { recursive: true, force: true }).catch(() => {});
  await mkdir(join(EVIDENCE_DIR, "bundles"), { recursive: true });
  await mkdir(join(EVIDENCE_DIR, "receipts"), { recursive: true });

  // Full delegation chain (leaf..root), canonical wire JSON.
  const certs: DelegationCert[] = chain.delegations;
  await writeFile(
    join(EVIDENCE_DIR, "delegation-chain.json"),
    JSON.stringify({ certs: certs.map((c) => JSON.parse(encodeDelegationCert(c))) }, null, 2) + "\n",
  );

  for (const claim of claims) {
    await writeFile(join(EVIDENCE_DIR, "bundles", `${claim.label}.json`), encodeProofBundle(claim.bundle) + "\n");
    await writeFile(join(EVIDENCE_DIR, "receipts", `${claim.label}.json`), encodeVerificationReceipt(claim.receipt) + "\n");
  }

  const manifest: ManifestFile = {
    target_resource_id: TARGET_RESOURCE_ID,
    bound_path_prefix: "/docs",
    verifier_id: VERIFIER_ID,
    revoked_certs: [chain.rootCert.cert_id],
    claims: claims.map((c) => ({
      label: c.label,
      sha: c.sha,
      requested_path: c.requestedPath,
      verified_at: c.verifiedAt,
      expected_decision: c.expectedDecision,
      revoked: c.revoked,
    })),
  };
  await writeFile(join(EVIDENCE_DIR, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function verifyAt(i: number): number {
  return 1_700_000_000 + 60 * (i + 1);
}

async function bundleFor(chain: Chain, label: string, requestedPath: string, now = verifyAt(0)): Promise<ProofBundle> {
  return buildBundle(chain.implAgent, chain.implPriv, chain.delegations, deterministicChallenge(label), now);
}

async function issueReceipt(
  bundle: ProofBundle,
  result: Awaited<ReturnType<typeof verifyBundle>>,
  prev: Uint8Array | null,
  now: number,
): Promise<VerificationReceipt> {
  const vk = await demoKeypair("verifier");
  return issueVerificationReceipt(bundle, result, VERIFIER_ID, vk.publicKey, vk.privateKey, prev, now);
}

function assert(cond: boolean, msg: string): asserts cond {
  if (!cond) throw new Error(msg);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const chain = await scene1_delegation();
  await scene2_handoff(chain);
  sceneParserBoundaries();
  await sceneFederation();
  const commitClaims = await scene3_work_with_receipts(chain);
  const killClaim = await scene4_kill_switch(chain, commitClaims);
  const claims = [...commitClaims, killClaim];
  const { verified, total } = await scene5_publish_and_reverify(chain, claims);

  console.log("");
  const annex = await runAnnex();
  console.log("");

  const line = `engagement: ${verified}/${total} verified, ${annex.refused}/${annex.total} refused`;
  console.log(line);

  const ok = verified === total && annex.refused === annex.total;
  if (!ok) {
    console.error("engagement: FAILED: not every claim re-verified or not every adversarial case refused");
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("engagement: FAILED:", err instanceof Error ? err.stack ?? err.message : err);
  process.exit(1);
});
