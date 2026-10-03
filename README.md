# Nottana crypto core

The client-side cryptography that decides whether "the server cannot read your
vault" is true.

Published so that claim can be checked rather than taken on trust. These are the
same files that run in the Nottana web app, copied verbatim from the product
repository at the commit named below.

Companion document: [Nottana Security Architecture](https://app.nottana.com/security-architecture.md),
which describes what is encrypted with what, where keys live, what our servers
can see, and the limits.

## What is here

| File | What it decides |
| --- | --- |
| `src/decrypt-core.js` | The item encryption format: algorithm, IV length, the `v2:` envelope, key normalisation, and decryption for both formats |
| `src/master-key-unwrap-core.js` | How a password becomes a key (PBKDF2-HMAC-SHA256, 600,000 iterations, per-user 16-byte salt) and how the master key is unwrapped |
| `src/pki-encryption.js` | RSA-OAEP 2048 with SHA-256, and the authenticated `gcm2:` hybrid envelope used to seal share keys to a recipient |
| `src/kdf-migration-bucket.js` | Which key derivation an account is on |

938 lines. Each file imports only `crypto-browserify` and a `Buffer` polyfill,
or the browser's own WebCrypto. None of them touches `document`, `window`,
`localStorage`, cookies or the network, which is what makes them readable on
their own.

## What publishing this proves, and what it does not

**It proves** the algorithms and parameters are what we say: that derivation is
PBKDF2-HMAC-SHA256 at 600,000 iterations rather than something weaker, that items
are sealed with AES-256-GCM, that share keys are wrapped with RSA-OAEP, and that
nothing here transmits a key anywhere.

**It does not prove** the bundle your browser executed was built from this source.
A server can serve different code to different users without detection, which is
the structural limit of all browser-delivered end-to-end encryption. We publish a
per-release hash manifest at `/build-manifest.json` so you can at least confirm
you received the same bundle as everyone else. Reproducible builds, which would
close the gap properly, are scoped and not done.

**It is not a security audit.** We have not had one. Reading this code is reading
our work, not an independent review of it.

## Reading notes

The comments are part of what is published. Several of them describe defects we
found and closed, including an unauthenticated hybrid envelope that was fixed
before this was first published. Those are left in because a file that records
only the decisions that went well describes a system nobody operates.

Two constants are for data written in older formats and are kept so that data can
still be read: `algorithm = "aes-256-cbc"` in `decrypt-core.js` and
`KDF_V1_VERSION` in `master-key-unwrap-core.js`. Each says so where it is
defined. New writes use AES-256-GCM and PBKDF2-600k.

You will find no measured figures here, such as how many accounts remain on an
older format. A code comment carries no date, so a number in one goes stale
without anyone noticing. Those live in the architecture document, which is
versioned.

## Provenance

| | |
| --- | --- |
| Web app version | 1.46.4 |
| Source commit | `6d92eefa9334bffe0c43bafdb6a3c4e2dc898c20` |
| Copied | 2026-10-03 |

Updated on each release that changes these files. If this copy ever disagrees
with what the product serves, that is a defect and we want to hear about it.

## Found something wrong?

That is the point of this repository. Open an issue here, or email
**security@nottana.com** for anything you would rather not post publicly.

A line in the architecture document that this code contradicts is a bug of the
same severity as the behaviour it misdescribes.

## Licence

Copyright © Nottana. All rights reserved.

Published for inspection and verification. You may read, fork and analyse it, and
quote from it when reporting a problem. It is not offered under an open-source
licence and is not licensed for reuse in other software.
