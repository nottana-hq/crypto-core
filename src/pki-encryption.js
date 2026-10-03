/**
 * Frontend PKI encryption utilities for notifications
 * Uses Web Crypto API for RSA encryption/decryption
 */

/**
 * Generate RSA key pair for notification encryption
 * @returns {Promise<Object>} Object containing publicKey and privateKey
 */
export const generateNotificationKeyPair = async () => {
  try {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true, // extractable
      ["encrypt", "decrypt"],
    );

    // Export public key
    const publicKeyBuffer = await crypto.subtle.exportKey(
      "spki",
      keyPair.publicKey,
    );
    const publicKeyPem = arrayBufferToPEM(publicKeyBuffer, "PUBLIC KEY");

    // Export private key
    const privateKeyBuffer = await crypto.subtle.exportKey(
      "pkcs8",
      keyPair.privateKey,
    );
    const privateKeyPem = arrayBufferToPEM(privateKeyBuffer, "PRIVATE KEY");

    console.log(
      "[PKI_ENCRYPTION] Notification key pair generated successfully",
    );

    return {
      publicKey: publicKeyPem,
      privateKey: privateKeyPem,
      keyPair, // Keep Web Crypto API key pair for direct use
    };
  } catch (error) {
    console.error(
      "[PKI_ENCRYPTION_ERROR] Failed to generate notification key pair:",
      error,
    );
    throw new Error("Failed to generate notification key pair");
  }
};

/**
 * Convert ArrayBuffer to PEM format
 * @param {ArrayBuffer} buffer - ArrayBuffer to convert
 * @param {string} type - PEM header type (PUBLIC KEY, PRIVATE KEY)
 * @returns {string} PEM formatted string
 */
const arrayBufferToPEM = (buffer, type) => {
  const bytes = new Uint8Array(buffer);
  const base64 = btoa(String.fromCharCode(...bytes));
  const chunks = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${type}-----\n${chunks.join("\n")}\n-----END ${type}-----\n`;
};

/**
 * Convert PEM string to ArrayBuffer
 * @param {string} pem - PEM formatted string
 * @returns {ArrayBuffer} ArrayBuffer
 */
const pemToArrayBuffer = (pem) => {
  const base64 = pem
    .replace(/-----BEGIN [\w\s]+ KEY-----/g, "")
    .replace(/-----END [\w\s]+ KEY-----/g, "")
    .replace(/\s/g, "");
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
};

/**
 * Import public key from PEM format
 * @param {string} publicKeyPem - Public key in PEM format
 * @returns {Promise<CryptoKey>} Web Crypto API public key
 */
const importPublicKey = async (publicKeyPem) => {
  try {
    const keyBuffer = pemToArrayBuffer(publicKeyPem);
    return await crypto.subtle.importKey(
      "spki",
      keyBuffer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256",
      },
      false, // not extractable
      ["encrypt"],
    );
  } catch (error) {
    console.error("[PKI_ENCRYPTION] Failed to import public key:", error);
    throw new Error("Failed to import public key");
  }
};

/**
 * Import private key from PEM format
 * @param {string} privateKeyPem - Private key in PEM format
 * @returns {Promise<CryptoKey>} Web Crypto API private key
 */
const importPrivateKey = async (privateKeyPem) => {
  try {
    const keyBuffer = pemToArrayBuffer(privateKeyPem);
    return await crypto.subtle.importKey(
      "pkcs8",
      keyBuffer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256",
      },
      false, // not extractable
      ["decrypt"],
    );
  } catch (error) {
    console.error("[PKI_ENCRYPTION] Failed to import private key:", error);
    throw new Error("Failed to import private key");
  }
};

/**
 * Encrypt data using RSA public key (for notifications)
 * @param {Object|string} data - Data to encrypt
 * @param {string} publicKeyPem - Recipient's public key in PEM format
 * @returns {Promise<string>} Encrypted data as base64 string
 */
/**
 * Envelope marker for the authenticated (AES-GCM) hybrid format.
 *
 * Legacy envelopes are `iv:key:data` (3 parts, AES-CBC, unauthenticated) and are
 * still DECRYPTED for compatibility; nothing writes them any more.
 */
export const HYBRID_GCM_PREFIX = "gcm2";

export const encryptWithPublicKey = async (data, publicKeyPem) => {
  try {
    if (!publicKeyPem) {
      throw new Error("Public key is required for encryption");
    }

    // Convert data to string if it's an object
    const dataString = typeof data === "string" ? data : JSON.stringify(data);
    const dataBuffer = new TextEncoder().encode(dataString);

    // RSA-OAEP can encrypt up to ~190 bytes for 2048-bit key
    // For larger data, use hybrid encryption
    const maxRSAEncryptSize = 190;

    if (dataBuffer.length <= maxRSAEncryptSize) {
      // Small data: encrypt directly with RSA
      const publicKey = await importPublicKey(publicKeyPem);
      const encrypted = await crypto.subtle.encrypt(
        {
          name: "RSA-OAEP",
        },
        publicKey,
        dataBuffer,
      );

      return arrayBufferToBase64(encrypted);
    } else {
      /*
        Large data: hybrid encryption, AUTHENTICATED.

        This branch used to use AES-CBC with no MAC, which is malleable: anyone
        able to modify the ciphertext in transit could flip plaintext bits and
        nothing would detect it. It was never reachable in production, because the
        two things that go through this function, the CLI key handoff and share
        keys, are both 32-byte keys and take the <=190-byte direct RSA-OAEP path
        above, where tampering fails OAEP padding. But "unreachable" was a
        property of the CALLERS, not of this function; one future caller with a
        larger payload would have silently got unauthenticated encryption.

        Same shape as an earlier offline-cache defect that wrote plaintext on a
        fallback path, and closed for the same reason. This file is published as
        part of the crypto core, so it is read as the advertised design.

        GCM's 12-byte IV is the NIST-recommended size; WebCrypto appends the
        128-bit auth tag to the ciphertext, so decrypt rejects any modification.
      */
      const aesKey = await crypto.subtle.generateKey(
        {
          name: "AES-GCM",
          length: 256,
        },
        true,
        ["encrypt"],
      );

      const iv = crypto.getRandomValues(new Uint8Array(12));

      const encryptedData = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: iv,
        },
        aesKey,
        dataBuffer,
      );

      // Export AES key
      const exportedAESKey = await crypto.subtle.exportKey("raw", aesKey);

      // Encrypt AES key with RSA public key
      const publicKey = await importPublicKey(publicKeyPem);
      const encryptedAESKey = await crypto.subtle.encrypt(
        {
          name: "RSA-OAEP",
        },
        publicKey,
        exportedAESKey,
      );

      // Return: gcm2:iv:encryptedAESKey:encryptedData (all base64).
      //
      // The version marker is what lets decrypt tell this from the legacy
      // 3-part CBC envelope without guessing. Base64 never contains ":", so
      // splitting on it is unambiguous.
      return `${HYBRID_GCM_PREFIX}:${arrayBufferToBase64(iv)}:${arrayBufferToBase64(encryptedAESKey)}:${arrayBufferToBase64(encryptedData)}`;
    }
  } catch (error) {
    console.error("[PKI_ENCRYPTION] Failed to encrypt with public key:", error);
    throw new Error("Failed to encrypt data with public key");
  }
};

/**
 * Decrypt data using RSA private key (for notifications)
 * @param {string} encryptedData - Encrypted data as base64 string
 * @param {string} privateKeyPem - Recipient's private key in PEM format
 * @returns {Promise<Object|string>} Decrypted data
 */
export const decryptWithPrivateKey = async (encryptedData, privateKeyPem) => {
  try {
    if (!privateKeyPem) {
      throw new Error("Private key is required for decryption");
    }

    const parts = encryptedData.split(":");

    if (parts.length === 1) {
      // Small data: encrypted directly with RSA
      const privateKey = await importPrivateKey(privateKeyPem);
      const encryptedBuffer = base64ToArrayBuffer(encryptedData);
      const decrypted = await crypto.subtle.decrypt(
        {
          name: "RSA-OAEP",
        },
        privateKey,
        encryptedBuffer,
      );

      const decryptedString = new TextDecoder().decode(decrypted);
      // Try to parse as JSON, return string if not valid JSON
      try {
        return JSON.parse(decryptedString);
      } catch {
        return decryptedString;
      }
    } else if (
      parts.length === 3 ||
      (parts.length === 4 && parts[0] === HYBRID_GCM_PREFIX)
    ) {
      // Large data: hybrid encryption
      /*
        TWO HYBRID ENVELOPES, and the marker says which.

          gcm2:iv:key:data  AES-256-GCM, authenticated. What we write.
          iv:key:data       AES-256-CBC, UNAUTHENTICATED. Legacy, read-only.

        The CBC branch stays so anything written before the switch still opens.
        Nothing produces it any more. It was never reachable in production
        anyway, since both real callers send 32-byte keys and take the direct
        RSA-OAEP path. Decrypting it costs nothing, and removing it could strand
        data we have not proven does not exist.
      */
      const isAuthenticated = parts.length === 4 && parts[0] === HYBRID_GCM_PREFIX;
      const [ivBase64, encryptedAESKeyBase64, encryptedDataBase64] =
        isAuthenticated ? parts.slice(1) : parts;
      const algorithm = isAuthenticated ? "AES-GCM" : "AES-CBC";

      // Decrypt AES key with RSA private key
      const privateKey = await importPrivateKey(privateKeyPem);
      const encryptedAESKeyBuffer = base64ToArrayBuffer(encryptedAESKeyBase64);
      const decryptedAESKeyBuffer = await crypto.subtle.decrypt(
        {
          name: "RSA-OAEP",
        },
        privateKey,
        encryptedAESKeyBuffer,
      );

      // Import AES key
      const aesKey = await crypto.subtle.importKey(
        "raw",
        decryptedAESKeyBuffer,
        {
          name: algorithm,
          length: 256,
        },
        false,
        ["decrypt"],
      );

      // Decrypt data with AES key
      const iv = base64ToArrayBuffer(ivBase64);
      const encryptedDataBuffer = base64ToArrayBuffer(encryptedDataBase64);
      // GCM throws here on ANY modification, which is the whole point of the
      // change. CBC would have returned attacker-chosen plaintext instead.
      const decryptedData = await crypto.subtle.decrypt(
        {
          name: algorithm,
          iv: iv,
        },
        aesKey,
        encryptedDataBuffer,
      );

      const decryptedString = new TextDecoder().decode(decryptedData);
      // Try to parse as JSON, return string if not valid JSON
      try {
        return JSON.parse(decryptedString);
      } catch {
        return decryptedString;
      }
    } else {
      throw new Error("Invalid encrypted data format");
    }
  } catch (error) {
    console.error(
      "[PKI_ENCRYPTION] Failed to decrypt with private key:",
      error,
    );
    throw new Error("Failed to decrypt data with private key");
  }
};

/**
 * Convert ArrayBuffer to base64 string
 * @param {ArrayBuffer} buffer - ArrayBuffer to convert
 * @returns {string} Base64 string
 */
const arrayBufferToBase64 = (buffer) => {
  const bytes = new Uint8Array(buffer);
  return btoa(String.fromCharCode(...bytes));
};

/**
 * Convert base64 string to ArrayBuffer
 * @param {string} base64 - Base64 string
 * @returns {ArrayBuffer} ArrayBuffer
 */
const base64ToArrayBuffer = (base64) => {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
};

/**
 * Verify that a public key and private key are a matching RSA key pair
 * by attempting to encrypt with public key and decrypt with private key
 * @param {string} publicKeyPem - Public key in PEM format
 * @param {string} privateKeyPem - Private key in PEM format
 * @returns {Promise<boolean>} True if keys match, false otherwise
 */
export const verifyKeyPairMatch = async (publicKeyPem, privateKeyPem) => {
  try {
    if (!publicKeyPem || !privateKeyPem) {
      return false;
    }

    // Import both keys
    const publicKey = await importPublicKey(publicKeyPem);
    const privateKey = await importPrivateKey(privateKeyPem);

    // Test encryption/decryption with a small test message
    const testData = new TextEncoder().encode("test");
    const encrypted = await crypto.subtle.encrypt(
      {
        name: "RSA-OAEP",
      },
      publicKey,
      testData,
    );

    const decrypted = await crypto.subtle.decrypt(
      {
        name: "RSA-OAEP",
      },
      privateKey,
      encrypted,
    );

    // Compare decrypted data with original
    const decryptedString = new TextDecoder().decode(decrypted);
    return decryptedString === "test";
  } catch (error) {
    console.warn(
      "[PKI_ENCRYPTION] Key pair verification failed:",
      error.message,
    );
    return false;
  }
};
