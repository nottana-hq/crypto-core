/* eslint-disable no-console */
// Pure, DOM-free decryption core. Imports ONLY crypto-browserify + the Buffer
// polyfill, with no `document`, `window`, cookies or feature-flag state. That
// is what lets it run byte-identically on the main thread and inside a Web
// Worker. `encryption.js` and `share-encryption.js` re-export
// these so existing callers are unchanged and there is a single, shared crypto
// implementation with no forked behaviour.
//
// SECURITY: never log keys or decrypted plaintext here. This module only
// DECRYPTS. It never encrypts and holds no feature-flag state.
//
// That rule is HELD BY CONSTRUCTION rather than by care, because care was not
// enough: this file used to log the caught error from both decrypt paths, and
// both end in JSON.parse, whose error message can quote its input. So a decrypt
// that succeeded cryptographically but yielded non-JSON printed plaintext. The
// catches now emit a fixed code and field lengths, and nothing derived from an
// error's text reaches a log. See classifyDecryptFailure below.
import crypto from "crypto-browserify";
import * as buffer from "buffer";

const Buffer =
  (typeof globalThis !== "undefined" && globalThis.Buffer) ??
  buffer.Buffer ??
  buffer.default ??
  buffer;
if (typeof globalThis !== "undefined" && Buffer) {
  globalThis.Buffer = Buffer;
}

// AES-256-CBC, the legacy v1 format.
//
// Present so items written before the migration to AES-256-GCM can still be
// READ. Nothing in this module encrypts, so these constants describe old data
// rather than how new data is stored; V2_PREFIX below is the format writes
// produce today.
//
// Deliberately no count of how much v1 data remains. That number is a
// measurement taken on a date, and a comment carries neither, so it would be
// stale without anyone noticing. Dated figures live in the versioned security
// architecture document instead.
export const algorithm = "aes-256-cbc";
export const ivLength = 16;

// AES-256-GCM (v2) envelope: "v2:<iv-hex>:<ciphertext-hex>:<authTag-hex>".
export const V2_PREFIX = "v2:";

/**
 * Normalize a key to 32 bytes via SHA-256. This reformats rather than stretches,
 * which is safe for the high-entropy inputs the decrypt path uses: master key,
 * share key, session tokens. Kept in sync with the encrypt side by being the single
 * shared definition.
 *
 * @param {string|Buffer} key
 * @returns {Buffer} 32-byte key
 */
export const normalizeKey = (key) => {
  if (!key) {
    throw new Error("Key must not be empty");
  }
  return crypto.createHash("sha256").update(key).digest();
};


/*
  WHY FAILURES ARE LOGGED AS CODES AND NEVER AS MESSAGES.

  Both decrypt paths end in JSON.parse, and a V8 parse error message can quote
  an excerpt of its input. So a decrypt that succeeds cryptographically but
  yields non-JSON used to put PLAINTEXT in the console, through
  `console.error(..., err.message)`. An external review of the published copy of
  this file reproduced exactly that in October 2026 (summarised in the mirror's
  `llms.txt`, under "Closed, with tests"), and it contradicted this module's own
  header rule two screens above.

  The fix is not to reason case by case about which library messages are safe to
  print. In a file that decrypts a vault, the whole class goes: nothing derived
  from the caught error's text is logged, only a fixed code and lengths. An
  operator keeps the distinction between "wrong key" and "malformed envelope",
  which is what the log was for.
*/

/**
 * A malformed envelope, as distinct from a cipher that refused.
 *
 * WHY A CLASS AND NOT A MESSAGE. The legacy path validates INSIDE the try that
 * also runs the cipher, so without a type the catch could not tell "this
 * envelope has three parts" from "the tag did not authenticate" - and the first
 * version of this change logged a malformed envelope as `auth-failed`, which is
 * exactly the wrong thing to tell whoever is reading the log at 2am. The class
 * carries the distinction; the message stays a fixed string.
 */
export class EnvelopeFormatError extends Error {
  constructor(message) {
    super(message);
    this.name = "EnvelopeFormatError";
  }
}

/** Fixed failure codes. Stable strings, safe to log, safe to grep for. */
export const DECRYPT_FAILURE = Object.freeze({
  AUTH_FAILED: "auth-failed",
  PLAINTEXT_NOT_JSON: "plaintext-not-json",
  MALFORMED: "malformed-envelope",
  KEY_REJECTED: "key-rejected",
  UNKNOWN: "unknown",
});

/**
 * Map a caught error to a code WITHOUT reading its message.
 *
 * `JSON.parse` throws SyntaxError, and that is the one whose message can carry
 * plaintext — so it is identified by TYPE, never by text. The remaining classes
 * are distinguished by `name`, which is library-assigned and carries no input.
 *
 * @param {unknown} err
 * @returns {string} one of DECRYPT_FAILURE
 */
export const classifyDecryptFailure = (err) => {
  if (err instanceof EnvelopeFormatError || err?.name === "EnvelopeFormatError") {
    return DECRYPT_FAILURE.MALFORMED;
  }
  if (err instanceof SyntaxError) {
    return DECRYPT_FAILURE.PLAINTEXT_NOT_JSON;
  }
  if (err instanceof RangeError || err?.name === "RangeError") {
    return DECRYPT_FAILURE.KEY_REJECTED;
  }
  if (err?.name === "Error" || err instanceof Error) {
    // crypto-browserify and node both surface a GCM tag mismatch as a plain
    // Error from decipher.final(). Treated as the authentication failure it is.
    return DECRYPT_FAILURE.AUTH_FAILED;
  }
  return DECRYPT_FAILURE.UNKNOWN;
};

/**
 * Report a decrypt failure. Takes only values that cannot contain plaintext:
 * the envelope kind and byte/character counts.
 *
 * @param {string} envelope "v2-gcm" or "v1-cbc"
 * @param {unknown} err
 * @param {Record<string, number>} [sizes]
 */
const logDecryptFailure = (envelope, err, sizes = {}) => {
  console.error("[DECRYPTION ERROR] decrypt failed", {
    envelope,
    code: classifyDecryptFailure(err),
    ...sizes,
  });
};

/** Hex, and nothing but hex. Empty is not hex. */
const isHex = (value) =>
  typeof value === "string" && value.length > 0 && /^[0-9a-fA-F]+$/.test(value);

/**
 * Envelope field lengths, in HEX CHARACTERS, for the format this module's
 * encrypt counterpart writes: a 12-byte GCM IV and a 16-byte tag.
 *
 * Asserted for v2 only. A legacy CBC envelope was written by code that predates
 * this file, so its IV length is not something we can prove for every record
 * still out there, and refusing one would lock a user out of their own data to
 * satisfy a symmetry nobody asked for. Legacy is held to "two hex parts".
 */
const V2_IV_HEX_LENGTH = 24;
const V2_TAG_HEX_LENGTH = 32;

/**
 * Decrypt an AES-256-GCM ("v2:") envelope. Authenticated, so a wrong key or a
 * tampered ciphertext or authTag throws.
 *
 * THE FORMAT IS ENFORCED, not merely parsed: exactly three colon-separated
 * fields after the prefix, each hex, with a 24-character IV and a 32-character
 * tag. A fourth field used to be ignored and a non-hex tag suffix silently
 * truncated, because `Buffer.from(value, "hex")` stops at the first character
 * it cannot read instead of complaining.
 *
 * @param {string|Buffer} key
 * @param {string} encryptedData - "v2:iv:ciphertext:authTag"
 * @returns {Promise<any>} the parsed plaintext object
 * @throws {EnvelopeFormatError} the envelope is not that shape
 * @throws {Error} a generic failure for anything the cipher refused, so a
 *   caller cannot distinguish a wrong key from a tampered tag by the message
 */
export const decryptDataV2 = async (key, encryptedData) => {
  if (!encryptedData || typeof encryptedData !== "string") {
    throw new Error("Invalid encrypted data format received.");
  }
  if (!encryptedData.startsWith(V2_PREFIX)) {
    throw new Error("Not a v2 envelope.");
  }

  /*
    EXACTLY THREE PARTS, ALL HEX, FIXED IV AND TAG LENGTHS.

    Destructuring three names off `split(":")` ignores a fourth field, and
    `Buffer.from(x, "hex")` truncates at the first invalid character instead of
    complaining. Together that accepted an extra envelope field and a non-hex
    suffix on an otherwise valid tag, both reproduced by a public review. A
    primitive this file publishes should validate its own format.
  */
  const parts = encryptedData.slice(V2_PREFIX.length).split(":");
  if (parts.length !== 3) {
    throw new EnvelopeFormatError(
      "Invalid v2 envelope. Expected format: 'v2:iv:ciphertext:authTag'.",
    );
  }
  const [ivHex, ciphertextHex, authTagHex] = parts;
  if (!isHex(ivHex) || !isHex(ciphertextHex) || !isHex(authTagHex)) {
    throw new EnvelopeFormatError(
      "Invalid v2 envelope. Expected hex-encoded fields.",
    );
  }
  if (ivHex.length !== V2_IV_HEX_LENGTH || authTagHex.length !== V2_TAG_HEX_LENGTH) {
    throw new EnvelopeFormatError(
      "Invalid v2 envelope. Unexpected IV or authTag length.",
    );
  }

  try {
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      normalizeKey(key),
      Buffer.from(ivHex, "hex"),
    );
    decipher.setAuthTag(Buffer.from(authTagHex, "hex"));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(ciphertextHex, "hex")),
      decipher.final(),
    ]);
    return JSON.parse(decrypted.toString("utf8"));
  } catch (err) {
    logDecryptFailure("v2-gcm", err, {
      ivHexLength: ivHex.length,
      ciphertextHexLength: ciphertextHex.length,
      authTagHexLength: authTagHex.length,
    });
    throw new Error(
      "Failed to decrypt data. Ensure the key and format are correct.",
    );
  }
};

/**
 * Decrypt vault data, smart-detecting the envelope: a "v2:" prefix → AES-GCM,
 * otherwise legacy AES-CBC ("iv:ciphertext"). Accepts either a raw string, a
 * JSON string wrapping `{ data }`, or an object with a `data` field.
 *
 * The legacy envelope is held to exactly two hex fields and DELIBERATELY to no
 * length: it was written by code older than this file, so the IV length of
 * every record still out there is not something we can prove, and refusing one
 * would lock a reader out of their own data for symmetry with the v2 rules.
 *
 * @param {string|Buffer} key
 * @param {string|object} encryptedData
 * @returns {Promise<any>} the parsed plaintext object
 * @throws {EnvelopeFormatError} the envelope is neither shape
 * @throws {Error} a generic failure for anything the cipher refused
 */
export const decryptData = async (key, encryptedData) => {
  try {
    let dataString;

    // If it's a JSON string, parse it first
    if (typeof encryptedData === "string") {
      try {
        const parsedData = JSON.parse(encryptedData);
        if (parsedData.data) {
          dataString = parsedData.data;
        } else {
          dataString = encryptedData;
        }
      } catch {
        dataString = encryptedData;
      }
    } else if (typeof encryptedData === "object" && encryptedData.data) {
      dataString = encryptedData.data;
    } else {
      throw new Error("Invalid encrypted data format received.");
    }

    // Smart-detect: v2 envelope → AES-GCM path. Otherwise → legacy CBC path.
    if (typeof dataString === "string" && dataString.startsWith(V2_PREFIX)) {
      return await decryptDataV2(key, dataString);
    }

    // Now split the string directly
    /*
      EXACTLY TWO HEX PARTS, AND DELIBERATELY NO LENGTH ASSERTION.

      The part count and hex-ness are checked because a silently truncated
      Buffer.from is worse than a refusal. The IV LENGTH is not, because this
      envelope was written by code older than this file and we cannot prove the
      length of every record still out there. Refusing one would lock a user out
      of their own data to satisfy a symmetry with the v2 rules above.
    */
    const legacyParts = dataString.split(":");
    if (legacyParts.length !== 2) {
      throw new EnvelopeFormatError(
        "Invalid encrypted data structure. Expected format: 'IV:encryptedText'.",
      );
    }
    const [iv, encrypted] = legacyParts;
    if (!isHex(iv) || !isHex(encrypted)) {
      throw new EnvelopeFormatError(
        "Invalid encrypted data structure. Expected hex-encoded fields.",
      );
    }

    const normalizedKey = normalizeKey(key);

    const decipher = crypto.createDecipheriv(
      algorithm,
      normalizedKey,
      Buffer.from(iv, "hex"),
    );

    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return JSON.parse(decrypted);
  } catch (err) {
    /*
      The stack went too. It is produced inside the parse that failed, so it can
      quote the same input the message can, and "200 characters of it" is still
      plaintext.
    */
    logDecryptFailure("v1-cbc", err);
    /*
      A shape complaint keeps its own message, so this path says what the v2
      path says. Only a CIPHER failure collapses to the generic sentence, which
      is where vagueness is the point.
    */
    if (err instanceof EnvelopeFormatError) {
      throw err;
    }
    throw new Error(
      "Failed to decrypt data. Ensure the key and format are correct.",
    );
  }
};
