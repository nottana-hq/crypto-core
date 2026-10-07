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

**It proves** what these four files do, and that is narrower than it sounds. You
can read the derivation and see PBKDF2-HMAC-SHA256 at 600,000 iterations with a
per-user salt. You can read the `v2:` envelope and the RSA-OAEP hybrid and see
how they are opened. You can confirm that nothing here transmits a key anywhere,
because nothing here touches the network.

**It does not prove what the writers do**, because the writers are not here.
`decrypt-core.js` only decrypts. The code that seals an item lives in the
product repository, as do the callers, the feature flags that decide a cipher at
runtime, the deployment configuration and every line of the server. So "items
are sealed with AES-256-GCM" is a claim about the product, supported by the
architecture document and by what you can observe of the format these files
read. It is not a claim this repository on its own can settle, and an earlier
version of this section said otherwise.

Reading these files also tells you nothing about what our authentication backend
does with a credential it receives. That is the asymmetry an independent audit
would address, and we would rather name it than let four client files imply more
reach than they have.

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

You will find no measured figures IN THE SOURCE, such as how many records remain
on an older format. A code comment carries no date, so a number in one goes
stale without anyone noticing. Dated figures live in the architecture document,
which is versioned, and `llms.txt` beside this file repeats the few a reviewer
needs with the date attached.

## Provenance

| | |
| --- | --- |
| Web app version | 1.46.4 |
| Source commit | `af17b3440b60cb5a77833b412d4e68c5e0ccf6bc` |
| Copied | 2026-10-07 |

Updated on each release that changes these files. If this copy ever disagrees
with what the product serves, that is a defect and we want to hear about it.

## Checking it yourself

`package.json` pins both runtime dependencies to exact versions, and
`package-lock.json` pins everything under them, so two reviewers reach the same
answer rather than testing against whatever version happened to be installed. `test-vectors.json` holds fixed inputs and expected outputs, and
`verify.mjs` runs them:

```bash
npm install
node verify.mjs
```

The vectors cover the formats these files read, the refusals they owe you, and
the two findings a public review reproduced in October 2026 and which are now
closed: a decrypt failure must not put plaintext in a log, and an invalid salt
must be refused rather than silently truncated to nothing.

`llms.txt` states the same scope in a form an automated reviewer can read first.

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
