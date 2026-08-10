import { sha256 } from "@noble/hashes/sha2";
import { signBoth, verifyBoth, type HybridPrivateKey, type HybridPublicKey, type HybridSignature } from "@identities-ai/ratify-protocol";

export interface EvidenceCheckpoint {
  schema: "ratify-engagement-checkpoint/v1";
  evidence_id: string;
  manifest_sha256: string;
  head_receipt_sha256: string;
  claim_count: number;
  issued_at: number;
  signer_public_key: { ed25519: string; ml_dsa_65: string };
  signature: { ed25519: string; ml_dsa_65: string };
}

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64");
const unb64 = (s: string) => new Uint8Array(Buffer.from(s, "base64"));

export function checkpointSignBytes(c: Omit<EvidenceCheckpoint, "signature" | "signer_public_key">): Uint8Array {
  return new TextEncoder().encode(
    `${c.schema}\nevidence_id ${c.evidence_id}\nmanifest_sha256 ${c.manifest_sha256}\nhead_receipt_sha256 ${c.head_receipt_sha256}\nclaim_count ${c.claim_count}\nissued_at ${c.issued_at}\n`,
  );
}

export async function issueCheckpoint(manifest: Uint8Array, headReceipt: Uint8Array, claimCount: number, issuedAt: number, pub: HybridPublicKey, priv: HybridPrivateKey): Promise<EvidenceCheckpoint> {
  const unsigned = {
    schema: "ratify-engagement-checkpoint/v1" as const,
    evidence_id: "agent-relay-phase2-offline-v1",
    manifest_sha256: hex(sha256(manifest)),
    head_receipt_sha256: hex(sha256(headReceipt)),
    claim_count: claimCount,
    issued_at: issuedAt,
  };
  const signature = await signBoth(checkpointSignBytes(unsigned), priv);
  return { ...unsigned, signer_public_key: { ed25519: b64(pub.ed25519), ml_dsa_65: b64(pub.ml_dsa_65) }, signature: { ed25519: b64(signature.ed25519), ml_dsa_65: b64(signature.ml_dsa_65) } };
}

/**
 * Verify a checkpoint against the evidence it attests.
 *
 * `expectedSigner` is not optional in spirit. A checkpoint carries its own signer's
 * public key, so anyone who can rewrite the evidence can re-sign it with a fresh key
 * and every other check here still passes. The checkpoint only rules out truncation
 * once the signer is pinned to a value published somewhere the attacker does not
 * control, which is what the independently retained channel is for. Offline, the pin
 * is the deterministic demo verifier key and the circularity is the point: the model
 * is reproducible by anyone. Live, it is the deployment verifier key.
 */
export async function verifyCheckpoint(c: EvidenceCheckpoint, manifest: Uint8Array, headReceipt: Uint8Array, expectedSigner?: HybridPublicKey): Promise<string | null> {
  if (expectedSigner && (b64(expectedSigner.ed25519) !== c.signer_public_key.ed25519 || b64(expectedSigner.ml_dsa_65) !== c.signer_public_key.ml_dsa_65)) {
    return "unexpected checkpoint signer";
  }
  if (c.manifest_sha256 !== hex(sha256(manifest))) return "manifest hash mismatch";
  if (c.head_receipt_sha256 !== hex(sha256(headReceipt))) return "head receipt hash mismatch";
  const unsigned = { schema: c.schema, evidence_id: c.evidence_id, manifest_sha256: c.manifest_sha256, head_receipt_sha256: c.head_receipt_sha256, claim_count: c.claim_count, issued_at: c.issued_at };
  const pub: HybridPublicKey = { ed25519: unb64(c.signer_public_key.ed25519), ml_dsa_65: unb64(c.signer_public_key.ml_dsa_65) };
  const sig: HybridSignature = { ed25519: unb64(c.signature.ed25519), ml_dsa_65: unb64(c.signature.ml_dsa_65) };
  return verifyBoth(checkpointSignBytes(unsigned), sig, pub);
}
