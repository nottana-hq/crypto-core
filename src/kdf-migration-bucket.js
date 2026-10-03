// Classify a user's master-key KDF (key-derivation function) version for the
// admin KDF-migration dashboard.
//
// The master key is wrapped with a key derived from the user's password:
//   - V2 (current): PBKDF2-HMAC-SHA256, 600k iterations, brute-force resistant.
//   - V1 (legacy):  single-round SHA-256, with NO brute-force resistance. Users on
//                   V1 auto-upgrade to V2 on their next login with a
//                   v2-capable client (PATCH /auth/master-key-kdf).
//
// A user with no `masterKeyKdf.version` (or any non-V2 value) is treated as V1,
// matching the backend default `MASTER_KEY_KDF_V1 = "sha256-v1"` in routes/auth.js.
// Kept in lockstep with KDF_V2_VERSION in src/utils/encryption.js.

export const KDF_V2_VERSION = "pbkdf2-sha256-600k-v2";

/**
 * @param {string | null | undefined} version - user.masterKeyKdf?.version
 * @returns {"v2" | "v1"}
 */
export const classifyKdfVersion = (version) =>
  version === KDF_V2_VERSION ? "v2" : "v1";

/** True when the user is on the safe PBKDF2-600k KDF. */
export const isKdfV2 = (version) => classifyKdfVersion(version) === "v2";

// Display metadata for the dashboard (label + severity intent).
export const KDF_BUCKET_META = {
  v2: { label: "V2 — PBKDF2-600k (safe)", severity: "success" },
  v1: { label: "V1 — SHA-256 (legacy, migrate)", severity: "error" },
};
