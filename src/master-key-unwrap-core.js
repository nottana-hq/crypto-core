/**
 * Turning a master password into the master key. DOM-free, one implementation.
 *
 * WHY THIS FILE EXISTS. `encryption.js` holds these functions alongside code
 * that reaches for `document.cookie` and `localStorage`, so nothing outside a
 * browser can import it. The CLI needs exactly this unwrap for `nottana
 * unlock`, and copying it there would create a
 * SECOND implementation of the most safety-critical routine in the product.
 * A one-byte divergence makes every item un-openable and looks like data
 * corruption rather than a bug.
 *
 * This is the same split, for the same reason, that `decrypt-core.js` already
 * made for item decryption.
 * `encryption.js` re-exports everything below, so existing web callers are
 * untouched and there is still only one copy.
 *
 * MOVED VERBATIM. Nothing here was rewritten while relocating it. The parity
 * anchor is asserted in __tests__/master-key-unwrap-core.test.js against the
 * same vector as scripts/pbkdf2-parity-check.js, which also carries the Swift
 * and Web Crypto snippets:
 *
 *   password "correct horse battery staple"
 *   salt     0a1b2c3d4e5f60718293a4b5c6d7e8f9
 *   ->       4f272e1bff25aeeb4bf75e20e03f03ad37185e117ff3398fcfc6351d0f634f54
 *
 * DO NOT change the algorithm, the hash, the iteration count or the output
 * length here without re-running every platform in that script's header.
 */

/* eslint-disable no-console */
import crypto from "crypto-browserify";
import * as buffer from "buffer";
import { normalizeKey } from "./decrypt-core.js";

const Buffer =
  (typeof globalThis !== "undefined" && globalThis.Buffer) ??
  buffer.Buffer ??
  buffer.default ??
  buffer;
if (typeof globalThis !== "undefined" && Buffer) {
  globalThis.Buffer = Buffer;
}

// The legacy key derivation: a single round of SHA-256, with no salt and no
// brute-force resistance.
//
// Kept so an account that has not signed in since the migration can still have
// its master key unwrapped, which is the only way such an account can reach a
// client capable of upgrading it. Accounts move to V2 below on their next
// login, signup refuses V1 server-side, and a password reset writes V2.
//
// A reader meeting this constant first should read it as the format being
// migrated AWAY from. How many accounts remain on it is a measurement with a
// date, so it lives in the versioned security architecture document rather
// than in a comment that cannot carry one.
export const KDF_V1_VERSION = "sha256-v1";

// PBKDF2-HMAC-SHA256, 600,000 iterations, per-user 16-byte salt. The 600k
// figure is the OWASP recommendation for this construction.
export const KDF_V2_VERSION = "pbkdf2-sha256-600k-v2";
export const KDF_V2_ITERATIONS = 600000;
export const KDF_V2_SALT_BYTES = 16;

// performance.now() where available (monotonic, sub-ms), Date.now() otherwise.
const nowMs = () =>
  typeof performance !== "undefined" && typeof performance.now === "function"
    ? performance.now()
    : Date.now();

// Derive the 32-byte password-wrapping key via PBKDF2-HMAC-SHA256.
export const deriveWrappingKeyV2 = (password, saltHex) => {
  if (!password || !saltHex) {
    throw new Error("deriveWrappingKeyV2 requires password and saltHex.");
  }
  return crypto.pbkdf2Sync(
    Buffer.from(password, "utf8"),
    Buffer.from(saltHex, "hex"),
    KDF_V2_ITERATIONS,
    32,
    "sha256",
  );
};

/**
 * Same derivation, via WebCrypto. About 39x faster, and off the main thread.
 *
 * WHY THIS EXISTS. `pbkdf2Sync` above is a pure-JS implementation (WebCrypto's
 * PBKDF2 is async-only, so a *Sync function can never use it) and it runs
 * 600,000 SHA-256 rounds while BLOCKING the main thread. Measured on real
 * devices at 600k iterations:
 *
 *   Android (Chrome, 8 cores)   6237 ms   vs   160 ms native  (39.0x)
 *   iPhone  (Safari)            1004 ms
 *   Mac     (Chrome)            1501 ms   vs    38 ms native  (39.5x)
 *
 * A login unwraps twice, so Android users were frozen for 12.5 SECONDS on
 * every password login. That is the whole of the "slow login on mobile,
 * fine on desktop" report.
 *
 * IDENTICAL OUTPUT, NOT A NEW FORMAT. PBKDF2 is deterministic: same password,
 * salt, iteration count and length give the same 32 bytes, so nothing is
 * re-encrypted and no blob changes. The parity anchor above is asserted
 * against BOTH implementations in the tests.
 *
 * FALLS BACK TO THE SYNC PATH. `crypto.subtle` only exists in a secure context,
 * meaning https or localhost. Production is https (verified), but a dev server
 * on a LAN IP is not, and neither is an old WebView. There the sync path still runs,
 * exactly as before. This mirrors deriveShareKeyFromTokenAsync, which has
 * shipped this pattern in production for the share-key path.
 */
export const deriveWrappingKeyV2Async = async (password, saltHex, { onPath } = {}) => {
  if (!password || !saltHex) {
    throw new Error("deriveWrappingKeyV2Async requires password and saltHex.");
  }
  // `onPath` reports which branch actually ran. It exists because the fallback
  // below is SILENT, because its console.warn is stripped from production
  // builds. So "the fast path shipped" and "the fast path ran on this device"
  // are different claims and were indistinguishable. Native shells stayed slow
  // after this landed while browsers were fast, and nothing could tell the two
  // apart. Reporting is the caller's job; this module does no network.
  const report = (path, startedAt) => {
    try {
      onPath?.({ path, ms: Math.round(nowMs() - startedAt) });
    } catch (_) {
      // Telemetry must never break a login.
    }
  };
  const startedAt = nowMs();

  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    const key = deriveWrappingKeyV2(password, saltHex);
    report("unavailable", startedAt);
    return key;
  }
  try {
    const keyMaterial = await subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveBits"],
    );
    const bits = await subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: Buffer.from(saltHex, "hex"),
        iterations: KDF_V2_ITERATIONS,
        hash: "SHA-256",
      },
      keyMaterial,
      256,
    );
    const key = Buffer.from(new Uint8Array(bits));
    report("webcrypto", startedAt);
    return key;
  } catch (err) {
    // Never fail a login over a fast path. Any WebCrypto refusal (policy,
    // unsupported parameters, a locked-down WebView) falls back to the
    // implementation that has always run.
    console.warn(
      "[ENCRYPTION] WebCrypto PBKDF2 unavailable, using sync fallback:",
      err?.message || err,
    );
    const key = deriveWrappingKeyV2(password, saltHex);
    report("fallback", startedAt);
    return key;
  }
};

/**
 * Decrypt with an ALREADY-DERIVED wrapping key.
 *
 * A login unwraps the IV and then the master key, and both used to derive the
 * same 32 bytes independently from the same password and salt: 600,000
 * iterations, twice, for one identical answer. Passing the key in removes the
 * second derivation outright, which is the other half of the login fix.
 *
 * A key is passed rather than memoised on purpose: a module-level cache of
 * derived wrapping keys in a password manager raises lifetime and clearing
 * questions that a parameter does not.
 */
export const decryptIVV2WithKey = (encryptedIV, wrappingKey) => {
  try {
    if (!encryptedIV || !wrappingKey) {
      throw new Error("Missing required parameters for v2 IV decryption.");
    }
    const [ivForIVHex, encryptedHex, authTagHex] = encryptedIV.split(":");
    if (!ivForIVHex || !encryptedHex || !authTagHex) {
      throw new Error("Malformed encryptedIV. Missing components.");
    }
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      wrappingKey,
      Buffer.from(ivForIVHex, "hex"),
    );
    decipher.setAuthTag(Buffer.from(authTagHex, "hex"));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(encryptedHex, "hex")),
      decipher.final(),
    ]);
    return decrypted.toString("utf8");
  } catch (err) {
    console.error("[DECRYPTION ERROR] Failed to decrypt IV (v2):", err.message);
    throw new Error(
      "Unable to access your data. Please refresh the page and try again.",
    );
  }
};

/** Decrypt the master key with an ALREADY-DERIVED wrapping key. */
export const decryptMasterKeyV2WithKey = (
  encryptedMasterKey,
  iv,
  wrappingKey,
) => {
  try {
    if (!encryptedMasterKey || !iv || !wrappingKey) {
      throw new Error("Missing required parameters for v2 decryption.");
    }
    const [ciphertextHex, authTagHex] = encryptedMasterKey.split(":");
    if (!ciphertextHex || !authTagHex) {
      throw new Error(
        "Malformed encryptedMasterKey. Missing ciphertext or authTag.",
      );
    }
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      wrappingKey,
      Buffer.from(iv, "hex"),
    );
    decipher.setAuthTag(Buffer.from(authTagHex, "hex"));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(ciphertextHex, "hex")),
      decipher.final(),
    ]);
    return decrypted.toString("utf8");
  } catch (err) {
    console.error(
      "[DECRYPTION ERROR] Failed to decrypt master key (v2):",
      err.message,
    );
    throw new Error(
      "Decryption failed. Ensure the password, IV, and encrypted data are correct.",
    );
  }
};

export const decryptIV = (encryptedIV, password) => {
  try {
    if (!encryptedIV || !password) {
      throw new Error("Missing required parameters for IV decryption.");
    }

    const hashedPassword = normalizeKey(password);
    const [ivForIVHex, encryptedHex, authTagHex] = encryptedIV.split(":");

    if (!ivForIVHex || !encryptedHex || !authTagHex) {
      throw new Error("Malformed encryptedIV. Missing components.");
    }

    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      hashedPassword,
      Buffer.from(ivForIVHex, "hex"),
    );
    decipher.setAuthTag(Buffer.from(authTagHex, "hex"));

    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(encryptedHex, "hex")),
      decipher.final(),
    ]);

    return decrypted.toString("utf8");
  } catch (err) {
    console.error("[DECRYPTION ERROR] Failed to decrypt IV:", err.message);
    throw new Error(
      "Unable to access your data. Please refresh the page and try again.",
    );
  }
};

export const decryptMasterKey = (encryptedMasterKey, password, iv) => {
  try {
    if (!encryptedMasterKey || !password || !iv) {
      throw new Error("Missing required parameters for decryption.");
    }

    const hashedPassword = normalizeKey(password); // Normalize the inputted password

    const [ciphertextHex, authTagHex] = encryptedMasterKey.split(":");

    if (!ciphertextHex || !authTagHex) {
      throw new Error(
        "Malformed encryptedMasterKey. Missing ciphertext or authTag.",
      );
    }

    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      hashedPassword,
      Buffer.from(iv, "hex"),
    );
    decipher.setAuthTag(Buffer.from(authTagHex, "hex"));

    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(ciphertextHex, "hex")),
      decipher.final(),
    ]);

    return decrypted.toString("utf8");
  } catch (err) {
    console.error(
      "[DECRYPTION ERROR] Failed to decrypt master key:",
      err.message,
    );
    throw new Error(
      "Decryption failed. Ensure the password, IV, and encrypted data are correct.",
    );
  }
};

