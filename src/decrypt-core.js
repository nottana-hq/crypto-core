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

/**
 * Decrypt an AES-256-GCM ("v2:") envelope. Authenticated, so a wrong key or a
 * tampered ciphertext or authTag throws.
 *
 * @param {string|Buffer} key
 * @param {string} encryptedData - "v2:iv:ciphertext:authTag"
 * @returns {Promise<any>} the parsed plaintext object
 */
export const decryptDataV2 = async (key, encryptedData) => {
  if (!encryptedData || typeof encryptedData !== "string") {
    throw new Error("Invalid encrypted data format received.");
  }
  if (!encryptedData.startsWith(V2_PREFIX)) {
    throw new Error("Not a v2 envelope.");
  }

  const body = encryptedData.slice(V2_PREFIX.length);
  const [ivHex, ciphertextHex, authTagHex] = body.split(":");
  if (!ivHex || !ciphertextHex || !authTagHex) {
    throw new Error(
      "Invalid v2 envelope. Expected format: 'v2:iv:ciphertext:authTag'.",
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
    console.error("[DECRYPTION ERROR] Failed to decrypt data (v2):", err.message);
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
 * @param {string|Buffer} key
 * @param {string|object} encryptedData
 * @returns {Promise<any>} the parsed plaintext object
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
    const [iv, encrypted] = dataString.split(":");
    if (!iv || !encrypted) {
      throw new Error(
        "Invalid encrypted data structure. Expected format: 'IV:encryptedText'.",
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
    console.error("[DECRYPTION ERROR] Failed to decrypt data:", err.message);
    console.error("[DECRYPTION ERROR] Error details:", {
      name: err.name,
      message: err.message,
      stack: err.stack?.substring(0, 200) + "...",
    });
    throw new Error(
      "Failed to decrypt data. Ensure the key and format are correct.",
    );
  }
};
