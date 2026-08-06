/**
 * Re-verify a single published claim (one ProofBundle + its VerificationReceipt)
 * offline, with the open SDK. Usage:
 *
 *   npx tsx scripts/verify-one.ts <label>      # e.g. commit-1, killswitch
 *
 * Reads evidence/manifest.json to recover the verification context, decodes the
 * committed bundle and receipt, re-verifies both, and prints the identity_status.
 * Exits non-zero if the bundle does not reproduce the recorded decision or the
 * receipt signature / bundle-hash binding does not check out.
 */

import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  SCOPE_FILES_WRITE,
  bundleHash,
  decodeProofBundle,
  decodeVerificationReceipt,
  verifyBundle,
  verifyVerificationReceipt,
} from "@identities-ai/ratify-protocol";

import { SetRevocationProvider, buildVerificationContext } from "../src/harness.js";

const EVIDENCE_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "evidence");

interface ManifestClaim {
  label: string;
  requested_path: string;
  verified_at: number;
  expected_decision: string;
  revoked: boolean;
}
interface ManifestFile {
  revoked_certs: string[];
  claims: ManifestClaim[];
}

async function main(): Promise<void> {
  const label = process.argv[2];
  if (!label) {
    console.error("usage: tsx scripts/verify-one.ts <label>   (e.g. commit-1, killswitch)");
    process.exit(2);
  }
  const manifest = JSON.parse(await readFile(join(EVIDENCE_DIR, "manifest.json"), "utf8")) as ManifestFile;
  const entry = manifest.claims.find((c) => c.label === label);
  if (!entry) {
    console.error(`no claim labelled "${label}" in manifest`);
    process.exit(2);
  }

  const bundle = decodeProofBundle(await readFile(join(EVIDENCE_DIR, "bundles", `${label}.json`), "utf8"));
  const receipt = decodeVerificationReceipt(await readFile(join(EVIDENCE_DIR, "receipts", `${label}.json`), "utf8"));

  const res = await verifyBundle(bundle, {
    required_scope: SCOPE_FILES_WRITE,
    context: buildVerificationContext(entry.requested_path),
    now: entry.verified_at,
    ...(entry.revoked ? { revocation: new SetRevocationProvider(new Set(manifest.revoked_certs)) } : {}),
  });

  const sigErr = await verifyVerificationReceipt(receipt);
  const hashOk = bytesEqual(receipt.bundle_hash, bundleHash(bundle));

  console.log(`${label}: identity_status=${res.identity_status} (recorded ${entry.expected_decision})`);
  console.log(`${label}: receipt signature=${sigErr === null ? "ok" : `BAD (${sigErr})`} bundle_hash_binding=${hashOk ? "ok" : "BAD"}`);

  const ok = res.identity_status === entry.expected_decision && sigErr === null && hashOk;
  process.exit(ok ? 0 : 1);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

main().catch((err) => {
  console.error("verify-one: FAILED —", err instanceof Error ? err.message : err);
  process.exit(1);
});
