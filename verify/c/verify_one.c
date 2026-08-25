/*
 * Ratify Protocol, Phase 2 engagement: C verifier for the committed evidence.
 *
 * Re-verifies the committed evidence trail offline with the C SDK, consuming
 * the SAME committed bytes as the TypeScript / Go / Python / Rust verifiers.
 *
 * Coverage note (current C FFI surface):
 *   [x] bundle  -> identity_status  (ratify_verify_bundle_opts_v2)
 *   [x] receipt -> signature verify (ratify_receipt_verify)
 *   [ ] receipt -> bundle_hash binding  (NOT exposed: ratify_bundle_hash needs a
 *       RatifyProofBundle* handle and the FFI has no ratify_proof_bundle_from_json,
 *       nor an accessor for the receipt's stored bundle_hash field)
 *   [ ] receipt -> prev_hash chain link (NOT exposed: no accessor for the
 *       receipt's stored prev_hash field)
 * The two binding checks are covered by the Go / Rust / TypeScript lanes.
 *
 * The tiny fixed manifest (target resource id, revoked cert, and the four
 * claims) is embedded here so the C lane has no JSON dependency; it mirrors
 * evidence/manifest.json byte-for-byte.
 *
 * The include/library paths below assume a checkout of
 * github.com/identities-ai/ratify-protocol (tag v1.0.0-alpha.17) cloned as a
 * sibling of this repository.
 *
 * Build (macOS), from verify/c/ after `cargo build --release` in the C SDK:
 *   cc verify_one.c \
 *     -I ../../../ratify-protocol/sdks/c/include \
 *     -L ../../../ratify-protocol/sdks/c/target/release \
 *     -lratify_c -lpthread -framework Security -framework CoreFoundation \
 *     -o verify_one && ./verify_one
 *
 * Build (Linux): replace the two -framework flags with `-ldl -lm`.
 *
 * Exits non-zero if any supported check fails. Offline; no network.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ratify.h"

#define TARGET_RESOURCE_ID "git:github.com/identities-ai/ratify-agent-relay-engagement"
#define REVOKED_CERT       "demo-cert-root"

struct claim {
    const char *label;
    const char *requested_path;
    int64_t     verified_at;
    const char *expected_decision;
    int         revoked;
};

static const struct claim CLAIMS[] = {
    {"commit-1",   "/docs/getting-started.md", 1700000060, "authorized_agent", 0},
    {"commit-2",   "/docs/guides/install.md",  1700000120, "authorized_agent", 0},
    {"commit-3",   "/docs/index.md",           1700000180, "authorized_agent", 0},
    {"killswitch", "/docs/after-revocation.md",1700000240, "revoked",          1},
};
static const int N_CLAIMS = (int)(sizeof(CLAIMS) / sizeof(CLAIMS[0]));

/* Revocation callback: 1 = revoked. userdata is the revoked cert id. */
static int is_revoked(const char *cert_id, void *userdata)
{
    return strcmp(cert_id, (const char *)userdata) == 0 ? 1 : 0;
}

/* Read a whole file into a malloc'd null-terminated buffer, or NULL. */
static char *read_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)n, f);
    fclose(f);
    buf[got] = '\0';
    return buf;
}

int main(int argc, char **argv)
{
    const char *only_label = argc > 1 ? argv[1] : NULL;
    int failures = 0;
    int reported = 0;

    for (int i = 0; i < N_CLAIMS; i++) {
        const struct claim *c = &CLAIMS[i];
        if (only_label && strcmp(c->label, only_label) != 0) continue;
        reported++;

        char bundle_path[256], receipt_path[256];
        snprintf(bundle_path, sizeof bundle_path, "../../evidence/bundles/%s.json", c->label);
        snprintf(receipt_path, sizeof receipt_path, "../../evidence/receipts/%s.json", c->label);

        char *bundle_json  = read_file(bundle_path);
        char *receipt_json = read_file(receipt_path);
        if (!bundle_json || !receipt_json) {
            fprintf(stderr, "verify_one: FAILED: cannot read evidence for %s\n", c->label);
            free(bundle_json); free(receipt_json);
            return 1;
        }

        /* (1) bundle -> identity_status */
        RatifyResourceContext rc = {0};
        rc.requested_resource_id = TARGET_RESOURCE_ID;
        rc.requested_path        = c->requested_path;

        RatifyVerifyOptions opts = {0};
        opts.required_scope = "files:write";
        opts.now_unix       = c->verified_at;
        if (c->revoked) {
            opts.revocation_fn       = is_revoked;
            opts.revocation_userdata = (void *)REVOKED_CERT;
        }

        RatifyVerifyResult *result = NULL;
        char *err = NULL;
        ratify_verify_bundle_opts_v2(bundle_json, &opts, &rc, &result, &err);
        char *status = ratify_verify_result_identity_status(result);
        int bundle_ok = status && strcmp(status, c->expected_decision) == 0;
        printf("%s: identity_status=%s (recorded %s) %s\n",
               c->label, status ? status : "(null)", c->expected_decision,
               bundle_ok ? "OK" : "MISMATCH");
        ratify_string_free(status);
        ratify_error_free(err);
        ratify_verify_result_free(result);

        /* (2) receipt -> signature */
        char *rerr = NULL;
        RatifyStatus rs = ratify_receipt_verify(receipt_json, &rerr);
        int sig_ok = (rs == RatifyOk);
        printf("%s: receipt signature=%s (bundle_hash_binding + prev_hash_chain: covered by Go/Rust/TS) %s\n",
               c->label, sig_ok ? "ok" : "BAD", (bundle_ok && sig_ok) ? "OK" : "FAIL");
        ratify_error_free(rerr);

        if (!(bundle_ok && sig_ok)) failures++;

        free(bundle_json);
        free(receipt_json);
    }

    if (only_label && reported == 0) {
        fprintf(stderr, "verify_one: no claim labelled \"%s\"\n", only_label);
        return 2;
    }
    if (failures > 0) {
        fprintf(stderr, "verify_one: %d claim(s) FAILED\n", failures);
        return 1;
    }
    return 0;
}
