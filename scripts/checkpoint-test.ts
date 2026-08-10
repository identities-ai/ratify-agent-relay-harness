import { strict as assert } from "node:assert";
import { issueCheckpoint, verifyCheckpoint } from "../src/checkpoint.js";
import { demoKeypair } from "../src/harness.js";

const enc = new TextEncoder();
const key = await demoKeypair("verifier");
const manifest = enc.encode('{"claims":["a","b","c"]}\n');
const head = enc.encode('{"receipt":"c","prev":"b"}\n');
const cp = await issueCheckpoint(manifest, head, 3, 1700000240, key.publicKey, key.privateKey);

// Accept: the evidence the checkpoint was issued over, signed by the pinned signer.
assert.equal(await verifyCheckpoint(cp, manifest, head, key.publicKey), null);

// Refuse: the four ways the evidence set can be rewritten under a fixed checkpoint.
assert.equal(await verifyCheckpoint(cp, enc.encode('{"claims":["a","X","c"]}\n'), head, key.publicKey), "manifest hash mismatch", "mutation");
assert.equal(await verifyCheckpoint(cp, enc.encode('{"claims":["a","c"]}\n'), head, key.publicKey), "manifest hash mismatch", "middle deletion");
assert.equal(await verifyCheckpoint(cp, enc.encode('{"claims":["b","a","c"]}\n'), head, key.publicKey), "manifest hash mismatch", "reordering");
assert.equal(await verifyCheckpoint(cp, enc.encode('{"claims":["a","b"]}\n'), enc.encode('{"receipt":"b","prev":"a"}\n'), key.publicKey), "manifest hash mismatch", "suffix truncation");

// Refuse: the head receipt swapped while the manifest is left intact. Without this case
// the manifest hash short-circuits every negative above and the head binding is never
// actually exercised.
assert.equal(await verifyCheckpoint(cp, manifest, enc.encode('{"receipt":"b","prev":"a"}\n'), key.publicKey), "head receipt hash mismatch", "head receipt swap");

// Refuse: evidence rewritten and re-signed with an attacker's own key. This is the case
// the pinned signer exists for. Unpinned, the forgery verifies, which is why the signed
// head has to be published through a channel the repository's owner does not control.
const attacker = await demoKeypair("checkpoint-forger");
const forgedManifest = enc.encode('{"claims":["a","b"]}\n');
const forgedHead = enc.encode('{"receipt":"b","prev":"a"}\n');
const forged = await issueCheckpoint(forgedManifest, forgedHead, 2, 1700000240, attacker.publicKey, attacker.privateKey);
assert.equal(await verifyCheckpoint(forged, forgedManifest, forgedHead), null, "unpinned: forgery is self-consistent");
assert.equal(await verifyCheckpoint(forged, forgedManifest, forgedHead, key.publicKey), "unexpected checkpoint signer", "pinned: forgery refused");

console.log("checkpoint: valid + mutation/middle-deletion/reordering/suffix-truncation/head-swap/re-signed-forgery refused");
