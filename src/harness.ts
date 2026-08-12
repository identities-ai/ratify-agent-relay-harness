/**
 * Shared primitives for the Phase 2 engagement harness.
 *
 * Everything here is offline and deterministic: keys derive from fixed demo
 * seeds, challenges and commit shas derive from fixed labels, and all
 * timestamps derive from a single fixed base. Nothing calls the network.
 *
 * These are DEMO keys, clearly labelled, generated in-harness from fixed
 * seeds, never reused for anything real. Ratify supplies the portable proof;
 * Agent Relay's adapter + confinement (imported, not reimplemented here)
 * supply the middleware transport and the OS-enforced filesystem boundary.
 */

import { sha256 } from "@noble/hashes/sha2";
import {
  PROTOCOL_VERSION,
  SCOPE_FILES_WRITE,
  SCOPE_IDENTITY_DELEGATE,
  buildSessionContext,
  deriveID,
  hybridKeypairFromSeeds,
  issueDelegation,
  operationContextHash,
  signChallenge,
  type AgentIdentity,
  type DelegationCert,
  type HumanRoot,
  type HybridPrivateKey,
  type HybridSignature,
  type OperationContext,
  type ProofBundle,
  type RevocationProvider,
  type VerifierContext,
} from "@identities-ai/ratify-protocol";

// The target repo the delegation is bound to. Git profile: normalized,
// branch- and commit-independent, compared byte-for-byte (Ratify never
// dereferences it). Must be byte-identical in the cert constraint and in the
// verifier context, or the resource_path constraint fails closed.
export const TARGET_RESOURCE_ID =
  "git:github.com/identities-ai/ratify-agent-relay-engagement";
export const BOUND_PATH_PREFIX = "/docs";

// Two independent Relay deployment authorities (the federation scene). Each is a
// deployment's externally reachable API base host, the `<authority>` segment of
// `relay:v1:<authority>:<type>:<id>`. They are globally unique at a moment, so two
// deployments cannot mint colliding identifiers (RELAY-IDENTIFIER-PROFILE requirement #1).
export const CLIENT_DEPLOYMENT_AUTHORITY = "relay.ratifyprotocol.com";
export const CONTRACTOR_DEPLOYMENT_AUTHORITY = "ratify.agentrelay.com";

// A single fixed base time so every committed artifact is byte-deterministic.
// 2023-11-14T22:13:20Z. Injectable everywhere `now` is needed.
export const T0 = 1_700_000_000;
export const ISSUED_AT = T0;
export const EXPIRES_AT = T0 + 3600; // short expiry (1h), revocable

// Stable demo verifier identity used to sign VerificationReceipts.
export const VERIFIER_ID = "ratify-verifier-demo";

export function emptySig(): HybridSignature {
  return { ed25519: new Uint8Array(0), ml_dsa_65: new Uint8Array(0) };
}

/** Derive a deterministic demo hybrid keypair from a fixed label. */
export async function demoKeypair(label: string) {
  const edSeed = sha256(new TextEncoder().encode(`ratify-engagement-ed25519:${label}`));
  const mlSeed = sha256(new TextEncoder().encode(`ratify-engagement-mldsa65:${label}`));
  return hybridKeypairFromSeeds(edSeed, mlSeed);
}

/** A deterministic 32-byte challenge from a fixed label (offline stand-in for a verifier nonce). */
export function deterministicChallenge(label: string): Uint8Array {
  return sha256(new TextEncoder().encode(`ratify-engagement-challenge:${label}`));
}

/** A deterministic synthetic 40-hex commit sha (offline stand-in for a git commit). */
export function syntheticSha(label: string): string {
  const h = sha256(new TextEncoder().encode(`ratify-engagement-commit:${label}`));
  let out = "";
  for (const b of h.slice(0, 20)) out += b.toString(16).padStart(2, "0");
  return out;
}

/**
 * The verifier context for a verify-before-action check.
 *
 * The engagement's git-repo resource is bound here directly. The federation
 * dimension (deployment authority) is not threaded into this git context; it is
 * carried in the Relay channel resource_id and enforced by servesAuthority()
 * below. See the federation scene. Keep this context for the git-repo work.
 */
export function buildVerificationContext(
  requestedPath: string,
  resourceId: string = TARGET_RESOURCE_ID,
): VerifierContext {
  return {
    requested_resource_id: resourceId,
    requested_path: requestedPath,
    has_resource: true,
  };
}

// --- Federation: the deployment-authority namespace and its serve-or-refuse policy ---
// Answers "when authority crosses deployments, whose namespace does the resource live in?"
// (FEDERATION-NAMESPACE-RULE-2026-08-04.md). The `<authority>` fixes the namespace; a verifier
// serves exactly its own authority and refuses resources under any other. Authority-to-act and
// resource-namespace are orthogonal, so this is deployment/adapter policy; Ratify core still
// treats resource_id as opaque bytes compared by byte-equality (SPEC §5.7.3), unchanged.

/** Construct a Relay resource identifier: relay:v1:<authority>:<type>:<id>. */
export function relayResourceId(authority: string, type: string, id: string): string {
  return `relay:v1:${authority}:${type}:${id}`;
}

// v1 type enum (profile §1). No others are valid.
const RELAY_TYPES = new Set(["workspace", "channel", "dm", "node"]);

/** Canonical host per profile §1: DNS labels only, >= 2 labels, last label not all-digits, no loopback/mDNS. */
function isCanonicalHost(host: string): boolean {
  if (host.length === 0 || host.length > 253) return false;
  const labels = host.split(".");
  if (labels.length < 2) return false; // at least two labels
  for (const label of labels) {
    if (label.length < 1 || label.length > 63) return false;
    // charset a-z0-9-, no leading/trailing hyphen (single-char labels allowed)
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(label)) return false;
  }
  if (/^[0-9]+$/.test(labels[labels.length - 1]!)) return false; // last label all-digits => IPv4-like
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) return false;
  return true;
}

/** Canonical port per profile §1/§2: 1..65535, no leading zero, and 443 (the default) MUST be omitted. */
function isCanonicalPort(port: string): boolean {
  if (!/^[1-9][0-9]*$/.test(port)) return false; // digits, no leading zero (also rejects "0")
  const n = Number(port);
  return n >= 1 && n <= 65535 && n !== 443;
}

/** Snowflake per profile §4.0: [1-9][0-9]{0,19}, bounded to u64 max (§7.7). Regex guarantees BigInt parses. */
function isSnowflake(id: string): boolean {
  if (!/^[1-9][0-9]{0,19}$/.test(id)) return false;
  return BigInt(id) <= 18446744073709551615n;
}

/**
 * Canonical id per profile §4.0, the full per-type grammar: workspace/channel = Snowflake;
 * dm = Snowflake (group DM) OR dm_<24 lowercase hex> (1:1 digest); node = Snowflake OR
 * node_direct_<Snowflake> (implicit single-agent node, §4.4).
 */
function isCanonicalId(type: string, id: string): boolean {
  if (type === "dm" && id.startsWith("dm_")) return /^dm_[0-9a-f]{24}$/.test(id);
  if (type === "node" && id.startsWith("node_direct_")) return isSnowflake(id.slice("node_direct_".length));
  return isSnowflake(id);
}

/**
 * Parse a Relay resource_id, enforcing the v0.6 canonical grammar (profile §1): exactly 5 or 6
 * colon segments (6 only for a non-default port), `relay:v1:` prefix, canonical host, canonical
 * port when present, fixed type enum, canonical per-type id. Returns null for anything
 * non-canonical so the serve-authority check fails closed. This is the harness's structural
 * guard; the profile's own parser/validator remains the normative one.
 */
export function parseRelayResourceId(
  rid: string,
): { authority: string; type: string; id: string } | null {
  const parts = rid.split(":");
  if (parts.length < 5 || parts.length > 6) return null;
  if (parts[0] !== "relay" || parts[1] !== "v1") return null;

  const type = parts[parts.length - 2]!;
  const id = parts[parts.length - 1]!;
  if (!RELAY_TYPES.has(type) || !isCanonicalId(type, id)) return null;

  const auth = parts.slice(2, parts.length - 2); // 1 segment (host) or 2 (host, port)
  const host = auth[0]!;
  if (!isCanonicalHost(host)) return null;
  if (auth.length === 1) return { authority: host, type, id };
  const port = auth[1]!;
  if (!isCanonicalPort(port)) return null;
  return { authority: `${host}:${port}`, type, id };
}

/**
 * Deployment serve-authority policy (FEDERATION-NAMESPACE-RULE §3, the load-bearing rule).
 * A verifier serves exactly one deployment authority (its own externally reachable API base
 * host) and MUST refuse a resource-bound grant whose resource_id names an authority it does
 * not serve, even when the delegation is cryptographically valid. Byte-equality on the
 * `<authority>` component; anything not a well-formed Relay resource fails closed.
 */
export function servesAuthority(resourceId: string, servedAuthority: string): boolean {
  const parsed = parseRelayResourceId(resourceId);
  if (!parsed) return false; // not a Relay resource this deployment governs -> refuse
  return parsed.authority === servedAuthority;
}

/** Operation context identifying one specific action a proof authorizes. */
export function operationContextFor(
  requestedPath: string,
  operation: string,
): OperationContext {
  // TODO(federation): a host/deployment-authority field belongs here so the
  // same proof cannot be replayed against an identical operation on another host.
  return {
    required_scope: SCOPE_FILES_WRITE,
    operation,
    resource_id: TARGET_RESOURCE_ID,
    requested_path: requestedPath,
  };
}

/** 32-byte session_context binding a proof to one specific operation (SPEC §6.4.9). */
export function sessionContextFor(
  agentId: string,
  requestedPath: string,
  operation: string,
): Uint8Array {
  const request_hash = operationContextHash(operationContextFor(requestedPath, operation));
  return buildSessionContext({
    verifier_id: VERIFIER_ID,
    workspace_id: "agent-relay-demo",
    agent_id: agentId,
    session_id: "sess-1",
    invocation_id: operation,
    request_hash,
  });
}

/** An in-memory revocation provider backed by a set of revoked cert IDs (SPEC §17.1). */
export class SetRevocationProvider implements RevocationProvider {
  constructor(private readonly revoked: ReadonlySet<string>) {}
  async isRevoked(certID: string): Promise<[boolean, Error | null]> {
    return [this.revoked.has(certID), null];
  }
}

export interface ChainOpts {
  /** Root cert scope. Default grants files:write + identity:delegate (so the hop can sub-delegate). */
  rootScope?: string[];
  /** Leaf (implementation-agent) cert scope. Default narrows to files:write only. */
  leafScope?: string[];
  /** Cert expiry (both certs). Default EXPIRES_AT. */
  expiresAt?: number;
  /** resource_path prefix bound on both certs. Default /docs. */
  pathPrefix?: string;
  /** resource_id bound on both certs' resource_path constraint. Default the Git repo. */
  resourceId?: string;
  /** Label suffix so distinct chains get distinct demo keys. */
  label?: string;
}

export interface Chain {
  clientRoot: HumanRoot;
  clientRootPriv: HybridPrivateKey;
  leadAgent: AgentIdentity;
  leadPriv: HybridPrivateKey;
  implAgent: AgentIdentity;
  implPriv: HybridPrivateKey;
  rootCert: DelegationCert;
  leafCert: DelegationCert;
  /** Presentation order: [leaf, ..., root]. */
  delegations: DelegationCert[];
}

/**
 * Build a two-hop delegation chain:
 *   clientRoot --(rootCert)--> leadAgent --(leafCert)--> implAgent
 *
 * The client root signs rootCert; the lead agent signs leafCert (authority
 * narrows at the hop). This models the sub-delegation the Relay middleware
 * carries. The SDK is the source of truth for the certs; the middleware never
 * holds the keys.
 */
export async function buildChain(opts: ChainOpts = {}): Promise<Chain> {
  const rootScope = opts.rootScope ?? [SCOPE_FILES_WRITE, SCOPE_IDENTITY_DELEGATE];
  const leafScope = opts.leafScope ?? [SCOPE_FILES_WRITE];
  const expiresAt = opts.expiresAt ?? EXPIRES_AT;
  const pathPrefix = opts.pathPrefix ?? BOUND_PATH_PREFIX;
  const resourceId = opts.resourceId ?? TARGET_RESOURCE_ID;
  const suffix = opts.label ? `-${opts.label}` : "";

  const rkp = await demoKeypair(`client-root${suffix}`);
  const lkp = await demoKeypair(`lead-agent${suffix}`);
  const ikp = await demoKeypair(`impl-agent${suffix}`);

  const clientRoot: HumanRoot = {
    id: deriveID(rkp.publicKey),
    public_key: rkp.publicKey,
    created_at: T0,
  };
  const leadAgent: AgentIdentity = {
    id: deriveID(lkp.publicKey),
    public_key: lkp.publicKey,
    name: "lead-agent",
    agent_type: "orchestrator",
    created_at: T0,
  };
  const implAgent: AgentIdentity = {
    id: deriveID(ikp.publicKey),
    public_key: ikp.publicKey,
    name: "implementation-agent",
    agent_type: "worker",
    created_at: T0,
  };

  const rootCert: DelegationCert = {
    cert_id: `demo-cert-root${suffix}`,
    version: PROTOCOL_VERSION,
    issuer_id: clientRoot.id,
    issuer_pub_key: clientRoot.public_key,
    subject_id: leadAgent.id,
    subject_pub_key: leadAgent.public_key,
    scope: rootScope,
    constraints: [{ type: "resource_path", resource_id: resourceId, path_prefix: pathPrefix }],
    issued_at: ISSUED_AT,
    expires_at: expiresAt,
    signature: emptySig(),
  };
  await issueDelegation(rootCert, rkp.privateKey);

  const leafCert: DelegationCert = {
    cert_id: `demo-cert-leaf${suffix}`,
    version: PROTOCOL_VERSION,
    issuer_id: leadAgent.id,
    issuer_pub_key: leadAgent.public_key,
    subject_id: implAgent.id,
    subject_pub_key: implAgent.public_key,
    scope: leafScope,
    constraints: [{ type: "resource_path", resource_id: resourceId, path_prefix: pathPrefix }],
    issued_at: ISSUED_AT,
    expires_at: expiresAt,
    signature: emptySig(),
  };
  await issueDelegation(leafCert, lkp.privateKey);

  return {
    clientRoot,
    clientRootPriv: rkp.privateKey,
    leadAgent,
    leadPriv: lkp.privateKey,
    implAgent,
    implPriv: ikp.privateKey,
    rootCert,
    leafCert,
    delegations: [leafCert, rootCert],
  };
}

/** Build a ProofBundle the implementation agent presents to a verifier. */
export async function buildBundle(
  agent: AgentIdentity,
  agentPriv: HybridPrivateKey,
  delegations: DelegationCert[],
  challenge: Uint8Array,
  challengeAt: number,
  sessionContext?: Uint8Array,
): Promise<ProofBundle> {
  const challenge_sig = await signChallenge(challenge, challengeAt, agentPriv, sessionContext);
  const bundle: ProofBundle = {
    agent_id: agent.id,
    agent_pub_key: agent.public_key,
    delegations,
    challenge,
    challenge_at: challengeAt,
    challenge_sig,
  };
  if (sessionContext) bundle.session_context = sessionContext;
  return bundle;
}
