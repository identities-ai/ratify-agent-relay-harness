// Command verify_one re-verifies the committed Phase 2 evidence trail offline
// with the reference Go SDK — the SAME committed bytes the TypeScript
// scripts/verify-one.ts consumes. It decodes each ProofBundle and its
// VerificationReceipt, then checks, per claim:
//
//   (1) bundle  -> identity_status reproduces the recorded decision
//   (2) receipt -> signature verifies
//   (3) receipt -> bundle_hash binding matches BundleHash(bundle)
//   (4) receipt -> prev_hash chain link is intact (genesis = 32 zero bytes)
//
// Usage (from verify/go/):
//
//	go run .            # verify every claim in manifest order (checks the prev_hash chain)
//	go run . commit-1   # verify a single claim by label
//
// Exits non-zero if any check fails. Offline; no network.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	ratify "github.com/identities-ai/ratify-protocol"
)

type manifestClaim struct {
	Label            string `json:"label"`
	RequestedPath    string `json:"requested_path"`
	VerifiedAt       int64  `json:"verified_at"`
	ExpectedDecision string `json:"expected_decision"`
	Revoked          bool   `json:"revoked"`
}

type manifestFile struct {
	TargetResourceID string          `json:"target_resource_id"`
	RevokedCerts     []string        `json:"revoked_certs"`
	Claims           []manifestClaim `json:"claims"`
}

// setRevocationProvider is the Go analogue of the harness SetRevocationProvider:
// an in-memory revocation set (SPEC §17.1).
type setRevocationProvider struct{ revoked map[string]bool }

func (p setRevocationProvider) IsRevoked(certID string) (bool, error) {
	return p.revoked[certID], nil
}

func main() {
	// evidence/ sits two levels up from verify/go/.
	evidenceDir := filepath.Join("..", "..", "evidence")

	raw, err := os.ReadFile(filepath.Join(evidenceDir, "manifest.json"))
	if err != nil {
		fatal("reading manifest: %v", err)
	}
	var manifest manifestFile
	if err := json.Unmarshal(raw, &manifest); err != nil {
		fatal("parsing manifest: %v", err)
	}

	revoked := make(map[string]bool, len(manifest.RevokedCerts))
	for _, c := range manifest.RevokedCerts {
		revoked[c] = true
	}
	revocation := setRevocationProvider{revoked: revoked}

	// Optional single-label filter. Note: verifying one claim in isolation
	// still checks the prev_hash link against the preceding receipt in the
	// full chain, so we always walk the chain in order and only *report* the
	// requested label.
	onlyLabel := ""
	if len(os.Args) > 1 {
		onlyLabel = os.Args[1]
	}

	var prevReceiptHash []byte
	zero32 := make([]byte, 32)
	failures := 0
	reported := 0

	for _, entry := range manifest.Claims {
		bundleBytes, err := os.ReadFile(filepath.Join(evidenceDir, "bundles", entry.Label+".json"))
		if err != nil {
			fatal("reading bundle %s: %v", entry.Label, err)
		}
		receiptBytes, err := os.ReadFile(filepath.Join(evidenceDir, "receipts", entry.Label+".json"))
		if err != nil {
			fatal("reading receipt %s: %v", entry.Label, err)
		}

		bundle, err := ratify.DecodeProofBundle(bundleBytes)
		if err != nil {
			fatal("decoding bundle %s: %v", entry.Label, err)
		}
		receipt, err := ratify.DecodeVerificationReceipt(receiptBytes)
		if err != nil {
			fatal("decoding receipt %s: %v", entry.Label, err)
		}

		// (1) Re-verify the bundle; identity_status must reproduce the recorded decision.
		opts := ratify.VerifyOptions{
			RequiredScope: ratify.ScopeFilesWrite,
			Now:           time.Unix(entry.VerifiedAt, 0),
			Context: ratify.VerifierContext{
				RequestedResourceID: manifest.TargetResourceID,
				RequestedPath:       entry.RequestedPath,
				HasResource:         true,
			},
		}
		if entry.Revoked {
			opts.Revocation = revocation
		}
		res := ratify.Verify(bundle, opts)
		bundleOK := res.IdentityStatus == entry.ExpectedDecision

		// (2) Receipt signature.
		sigErr := ratify.VerifyVerificationReceipt(receipt)

		// (3) bundle_hash binding.
		bh, err := ratify.BundleHash(bundle)
		if err != nil {
			fatal("hashing bundle %s: %v", entry.Label, err)
		}
		hashOK := bytes.Equal(receipt.BundleHash, bh)

		// (4) prev_hash chain link.
		expectedPrev := prevReceiptHash
		if expectedPrev == nil {
			expectedPrev = zero32
		}
		chainOK := bytes.Equal(receipt.PrevHash, expectedPrev)

		// Advance the chain regardless of the label filter so links stay honest.
		rh, err := ratify.ReceiptHash(receipt)
		if err != nil {
			fatal("hashing receipt %s: %v", entry.Label, err)
		}
		prevReceiptHash = rh

		if onlyLabel != "" && entry.Label != onlyLabel {
			continue
		}
		reported++

		receiptOK := sigErr == nil && hashOK && chainOK
		claimOK := bundleOK && receiptOK
		if !claimOK {
			failures++
		}

		sig := "ok"
		if sigErr != nil {
			sig = fmt.Sprintf("BAD (%v)", sigErr)
		}
		fmt.Printf("%s: identity_status=%s (recorded %s) %s\n",
			entry.Label, res.IdentityStatus, entry.ExpectedDecision, okmiss(bundleOK, "OK", "MISMATCH"))
		fmt.Printf("%s: receipt signature=%s bundle_hash_binding=%s prev_hash_chain=%s %s\n",
			entry.Label, sig, okmiss(hashOK, "ok", "BAD"), okmiss(chainOK, "ok", "BROKEN"), okmiss(receiptOK, "OK", "FAIL"))
	}

	if onlyLabel != "" && reported == 0 {
		fatal("no claim labelled %q in manifest", onlyLabel)
	}
	if failures > 0 {
		fmt.Fprintf(os.Stderr, "verify_one: %d claim(s) FAILED\n", failures)
		os.Exit(1)
	}
}

func okmiss(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "verify_one: FAILED — "+format+"\n", args...)
	os.Exit(1)
}
