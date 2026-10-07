/**
 * Run the published test vectors against the published source.
 *
 *     npm install
 *     node verify.mjs
 *
 * WHY THIS EXISTS. A review of this repository in October 2026 had to build its
 * own harness against whatever `crypto-browserify` happened to be installed on
 * the reviewer's machine, and said so. Two reviewers could reach two answers for
 * reasons that have nothing to do with this code. Pinned dependencies plus fixed
 * vectors mean a disagreement is about the cryptography rather than the setup.
 *
 * WHAT IT CHECKS. Round trips for both envelope formats, the refusals these
 * primitives owe a caller, and the two findings that review reproduced:
 *
 *   1. a decrypt failure must not put plaintext in a log
 *   2. an invalid salt must be refused, not silently truncated to nothing
 *
 * Exits non-zero on any failure, so it can gate anything.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  fs.readFileSync(path.join(here, "test-vectors.json"), "utf8"),
);

const { decryptData, decryptDataV2, normalizeKey } = await import(
  path.join(here, "src/decrypt-core.js")
);
const { deriveWrappingKeyV2 } = await import(
  path.join(here, "src/master-key-unwrap-core.js")
);

let passed = 0;
const failures = [];

const check = (name, fn) => {
  try {
    const result = fn();
    if (result === true) {
      passed += 1;
      return;
    }
    failures.push(`${name}: ${result}`);
  } catch (err) {
    failures.push(`${name}: threw ${err?.name}: ${err?.message}`);
  }
};

const checkAsync = async (name, fn) => {
  try {
    const result = await fn();
    if (result === true) {
      passed += 1;
      return;
    }
    failures.push(`${name}: ${result}`);
  } catch (err) {
    failures.push(`${name}: threw ${err?.name}: ${err?.message}`);
  }
};

const rejects = async (name, fn, why) => {
  try {
    await fn();
    failures.push(`${name}: ACCEPTED ${why}, which it must refuse`);
  } catch {
    passed += 1;
  }
};

/* ---- key derivation ------------------------------------------------------ */

for (const vector of vectors.kdf.accepts) {
  check(`kdf accepts ${vector.label}`, () => {
    const key = deriveWrappingKeyV2(vector.password, vector.saltHex);
    return (
      key.toString("hex") === vector.expectedKeyHex ||
      `derived ${key.toString("hex")}, expected ${vector.expectedKeyHex}`
    );
  });
}

for (const vector of vectors.kdf.refuses) {
  await rejects(
    `kdf refuses ${vector.label}`,
    () => deriveWrappingKeyV2(vector.password ?? "password", vector.saltHex),
    JSON.stringify(vector.saltHex),
  );
}

check("two different invalid salts cannot share a derived key", () => {
  // The exact reproduction from the review. Both must refuse, so there is no
  // shared key left to compare.
  let refusedA = false;
  let refusedB = false;
  try {
    deriveWrappingKeyV2("pw", "zzzz");
  } catch {
    refusedA = true;
  }
  try {
    deriveWrappingKeyV2("pw", "not-hex-at-all");
  } catch {
    refusedB = true;
  }
  return (refusedA && refusedB) || "an invalid salt was still accepted";
});

/* ---- envelopes ----------------------------------------------------------- */

const sealV2 = (key, plaintext) => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", normalizeKey(key), iv);
  const body = Buffer.concat([
    cipher.update(Buffer.from(plaintext, "utf8")),
    cipher.final(),
  ]);
  return `v2:${iv.toString("hex")}:${body.toString("hex")}:${cipher
    .getAuthTag()
    .toString("hex")}`;
};

const sealLegacy = (key, plaintext) => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", normalizeKey(key), iv);
  return `${iv.toString("hex")}:${
    cipher.update(plaintext, "utf8", "hex") + cipher.final("hex")
  }`;
};

const inputKey = vectors.envelope.key;
const inputPayload = vectors.envelope.payload;

await checkAsync("v2 envelope round-trips", async () => {
  const actual = await decryptDataV2(
    inputKey,
    sealV2(inputKey, JSON.stringify(inputPayload)),
  );
  return (
    JSON.stringify(actual) === JSON.stringify(inputPayload) ||
    `got ${JSON.stringify(actual)}`
  );
});

await checkAsync("legacy envelope round-trips", async () => {
  const actual = await decryptData(
    inputKey,
    sealLegacy(inputKey, JSON.stringify(inputPayload)),
  );
  return (
    JSON.stringify(actual) === JSON.stringify(inputPayload) ||
    `got ${JSON.stringify(actual)}`
  );
});

await rejects(
  "v2 refuses a tampered authTag",
  () => {
    const sealed = sealV2(inputKey, JSON.stringify(inputPayload));
    const flipped = sealed.endsWith("aa") ? "bb" : "aa";
    return decryptDataV2(inputKey, sealed.slice(0, -2) + flipped);
  },
  "a tampered authentication tag",
);

await rejects(
  "v2 refuses a fourth field",
  () =>
    decryptDataV2(
      inputKey,
      `${sealV2(inputKey, JSON.stringify(inputPayload))}:extra`,
    ),
  "an extra envelope field",
);

await rejects(
  "v2 refuses a non-hex suffix on the authTag",
  () =>
    decryptDataV2(
      inputKey,
      `${sealV2(inputKey, JSON.stringify(inputPayload))}ZZZZ`,
    ),
  "a non-hex tag suffix",
);

await rejects(
  "v2 refuses the wrong key",
  () =>
    decryptDataV2(
      "a-different-key-entirely",
      sealV2(inputKey, JSON.stringify(inputPayload)),
    ),
  "the wrong key",
);

await rejects(
  "legacy refuses a third field",
  () =>
    decryptData(
      inputKey,
      `${sealLegacy(inputKey, JSON.stringify(inputPayload))}:extra`,
    ),
  "an extra envelope field",
);

await rejects(
  "legacy refuses non-hex fields",
  () => decryptData(inputKey, "nothex:alsonothex"),
  "non-hex fields",
);

/* ---- the log-leak finding ------------------------------------------------ */

await checkAsync(
  "a decrypt failure puts no plaintext in the log",
  async () => {
    const marker = vectors.logLeak.marker;
    const captured = [];
    const original = console.error;
    console.error = (...args) => {
      captured.push(args.map((a) => JSON.stringify(a)).join(" "));
    };
    try {
      // Decrypts correctly; the PLAINTEXT is malformed JSON, which is what made
      // JSON.parse quote it into the error message.
      await decryptDataV2(inputKey, sealV2(inputKey, `{"marker":"${marker}"`));
      return "the decrypt should have failed on invalid JSON";
    } catch {
      const logged = captured.join("\n");
      if (logged.includes(marker)) {
        return "PLAINTEXT APPEARED IN THE LOG";
      }
      return (
        logged.includes("plaintext-not-json") ||
        `expected a failure code in the log, got: ${logged}`
      );
    } finally {
      console.error = original;
    }
  },
);

await checkAsync("a failed decrypt logs no key material", async () => {
  const captured = [];
  const original = console.error;
  console.error = (...args) => {
    captured.push(args.map((a) => JSON.stringify(a)).join(" "));
  };
  try {
    await decryptDataV2(
      "a-different-key-entirely",
      sealV2(inputKey, JSON.stringify(inputPayload)),
    );
    return "the decrypt should have failed on the wrong key";
  } catch {
    const logged = captured.join("\n");
    return (
      (!logged.includes("a-different-key-entirely") &&
        !logged.includes(inputKey)) ||
      "a key appeared in the log"
    );
  } finally {
    console.error = original;
  }
});

/* ---- report -------------------------------------------------------------- */

if (failures.length > 0) {
  console.error(`\n${failures.length} FAILED, ${passed} passed\n`);
  failures.forEach((line) => console.error(`  FAIL  ${line}`));
  console.error(
    "\nIf you believe a failure is real, that is what security@nottana.com is for.",
  );
  process.exit(1);
}

console.log(`\nAll ${passed} checks passed.`);
console.log("Pinned: crypto-browserify 3.12.1, buffer 6.0.3 (see package.json).");
