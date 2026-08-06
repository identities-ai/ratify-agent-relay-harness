module ratify-phase2-verify

go 1.25

require github.com/identities-ai/ratify-protocol v0.0.0

require (
	github.com/cloudflare/circl v1.6.3 // indirect
	golang.org/x/sys v0.28.0 // indirect
)

// Local workspace SDK. The published reproduction pins the alpha.16 tag once cut.
replace github.com/identities-ai/ratify-protocol => ../../../ratify-protocol
