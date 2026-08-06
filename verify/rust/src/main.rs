//! Re-verify the committed Phase 2 evidence trail offline with the Rust SDK.
//!
//! Consumes the SAME committed bytes as the TypeScript / Go / Python verifiers.
//! For each claim it decodes the ProofBundle and its VerificationReceipt, then
//! checks:
//!   (1) bundle  -> identity_status reproduces the recorded decision
//!   (2) receipt -> signature verifies
//!   (3) receipt -> bundle_hash binding matches bundle_hash(bundle)
//!   (4) receipt -> prev_hash chain link is intact (genesis = 32 zero bytes)
//!
//! Usage (from verify/rust/):
//!   cargo run --release              # verify every claim in manifest order
//!   cargo run --release -- commit-1  # verify a single claim by label
//!
//! Exits non-zero if any check fails. Offline; no network.

use std::fs;
use std::path::PathBuf;
use std::process::exit;

use ratify_protocol::{
    bundle_hash, decode_proof_bundle, decode_verification_receipt, receipt_hash, verify_bundle,
    verify_verification_receipt, RevocationProvider, VerifierContext, VerifyOptions,
    SCOPE_FILES_WRITE,
};

/// In-memory revocation set (SPEC §17.1); Rust analogue of the harness provider.
struct SetRevocationProvider {
    revoked: std::collections::HashSet<String>,
}
impl RevocationProvider for SetRevocationProvider {
    fn is_revoked(&self, cert_id: &str) -> Result<bool, String> {
        Ok(self.revoked.contains(cert_id))
    }
}

fn okmiss(ok: bool, yes: &str, no: &str) -> String {
    if ok { yes.to_string() } else { no.to_string() }
}

fn main() {
    // evidence/ sits two levels up from verify/rust/.
    let evidence = PathBuf::from("..").join("..").join("evidence");

    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(evidence.join("manifest.json")).expect("read manifest"))
            .expect("parse manifest");
    let target_resource_id = manifest["target_resource_id"].as_str().unwrap().to_string();
    let revoked: std::collections::HashSet<String> = manifest["revoked_certs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    let only_label = std::env::args().nth(1).unwrap_or_default();

    let mut prev_receipt_hash: Option<Vec<u8>> = None;
    let zero32 = vec![0u8; 32];
    let mut failures = 0usize;
    let mut reported = 0usize;

    for entry in manifest["claims"].as_array().unwrap() {
        let label = entry["label"].as_str().unwrap();
        let requested_path = entry["requested_path"].as_str().unwrap().to_string();
        let verified_at = entry["verified_at"].as_i64().unwrap();
        let expected = entry["expected_decision"].as_str().unwrap();
        let is_revoked = entry["revoked"].as_bool().unwrap();

        let bundle_bytes = fs::read(evidence.join("bundles").join(format!("{label}.json"))).unwrap();
        let receipt_bytes = fs::read(evidence.join("receipts").join(format!("{label}.json"))).unwrap();

        let bundle = decode_proof_bundle(&bundle_bytes).expect("decode bundle");
        let receipt = decode_verification_receipt(&receipt_bytes).expect("decode receipt");

        // (1) Re-verify the bundle; identity_status must reproduce the recorded decision.
        let mut opts = VerifyOptions {
            required_scope: SCOPE_FILES_WRITE.to_string(),
            now: Some(verified_at),
            context: VerifierContext {
                requested_resource_id: Some(target_resource_id.clone()),
                requested_path: Some(requested_path.clone()),
                ..Default::default()
            },
            ..Default::default()
        };
        if is_revoked {
            opts.revocation = Some(Box::new(SetRevocationProvider { revoked: revoked.clone() }));
        }
        let res = verify_bundle(&bundle, &opts);
        let bundle_ok = res.identity_status.as_str() == expected;

        // (2) Receipt signature.
        let sig_err = verify_verification_receipt(&receipt);

        // (3) bundle_hash binding.
        let bh = bundle_hash(&bundle).expect("bundle_hash");
        let hash_ok = receipt.bundle_hash == bh;

        // (4) prev_hash chain link.
        let expected_prev = prev_receipt_hash.clone().unwrap_or_else(|| zero32.clone());
        let chain_ok = receipt.prev_hash == expected_prev;

        // Advance the chain regardless of the label filter so links stay honest.
        prev_receipt_hash = Some(receipt_hash(&receipt).expect("receipt_hash"));

        if !only_label.is_empty() && label != only_label {
            continue;
        }
        reported += 1;

        let receipt_ok = sig_err.is_ok() && hash_ok && chain_ok;
        if !(bundle_ok && receipt_ok) {
            failures += 1;
        }

        let sig = match &sig_err {
            Ok(()) => "ok".to_string(),
            Err(e) => format!("BAD ({e})"),
        };
        println!(
            "{label}: identity_status={} (recorded {expected}) {}",
            res.identity_status.as_str(),
            okmiss(bundle_ok, "OK", "MISMATCH")
        );
        println!(
            "{label}: receipt signature={sig} bundle_hash_binding={} prev_hash_chain={} {}",
            okmiss(hash_ok, "ok", "BAD"),
            okmiss(chain_ok, "ok", "BROKEN"),
            okmiss(receipt_ok, "OK", "FAIL")
        );
    }

    if !only_label.is_empty() && reported == 0 {
        eprintln!("verify_one: no claim labelled {only_label:?} in manifest");
        exit(2);
    }
    if failures > 0 {
        eprintln!("verify_one: {failures} claim(s) FAILED");
        exit(1);
    }
}
