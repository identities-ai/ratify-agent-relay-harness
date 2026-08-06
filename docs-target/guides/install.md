# Install

The example has no framework and few dependencies.

## Prerequisites

- A recent Node.js runtime.
- The published Ratify verification SDK for your language.

## Setup

1. Clone this repository.
2. Install dependencies.
3. Copy the sample configuration and set the verifier's trusted root key.

## Verify the install

Run the example's smoke check. It issues a proof, verifies it, and prints the resulting identity status. If you see an accepted status followed by a refused status on a tampered proof, the install is working.

## Notes

- This is example configuration only. Do not reuse these keys or settings outside the example.
- The verifier is offline by default. It makes no network call to accept or refuse a proof.
