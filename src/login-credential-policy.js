/**
 * What a sign-in puts on the wire, and when it may try again with more.
 *
 * THIS FILE IS PUBLISHED. It is one of the files mirrored to
 * github.com/nottana-hq/crypto-core, and it is here as a separate module for
 * that reason. The other published files prove the CRYPTOGRAPHY: how a
 * password becomes a key, how the master key is unwrapped, how the one-way
 * value is derived from it. None of them proves the claim people actually
 * care about, which is that the value is sent INSTEAD of the password. That
 * decision is this file, and leaving it inside a 5,000-line page component
 * meant the one piece of client code the claim rests on was the one piece
 * nobody outside could read.
 *
 * No imports, no DOM, no network, no storage. Everything it needs is an
 * argument, so it can be read on its own and tested without a browser.
 *
 * ## The protocol it implements
 *
 * `/auth/prelogin` supplies the salt and iteration count. With those the
 * client derives a one-way value from the password and sends THAT, with no
 * password in the body.
 *
 * A refusal is ambiguous on its own: "I hold no value to check for this
 * account" and "that credential is wrong" are both a 400. Retrying on either
 * meant an account that refuses its password still transmitted one whenever
 * its owner mistyped. So the server answers the ambiguity directly, with
 * `retryWithPassword`, and this file retries only when told to. See
 * utils/login-refusal-hint.js for how that answer avoids becoming a way to
 * find out which addresses have accounts.
 *
 * ## When it says yes, which is a migration and not a hole
 *
 * For an account that exists, the server permits the retry only while that
 * account still accepts a password, which is true in two situations. Both
 * are temporary and both are the migration finishing rather than a weaker
 * path staying open:
 *
 *   NO VALUE ESTABLISHED YET. An account that has never signed in from a
 *   client new enough to derive one has nothing for the server to check a
 *   hash against. The retry IS that account's sign-in, and the same request
 *   establishes its value. From the next sign-in onward it leads with the
 *   value and the password stays on the machine. This is the only route into
 *   the migrated state, which is why removing the retry would strand every
 *   account that has not taken it yet.
 *
 *   A VALUE THAT NO LONGER MATCHES, after a restored backup or a password
 *   changed out of band. The retry rescues it instead of leaving a correct
 *   password refused, and re-establishes the value on the way through.
 *
 * An account created on web 1.47.0 or later is in neither situation. It is
 * born holding a value and refusing passwords, so OUR server never answers
 * yes for it, from any browser, on any attempt. That is a property of what
 * the server sends, not of what this file enforces: see the note on
 * `mayRetryWithPassword` below.
 *
 *   AND A THIRD CASE, which is not an account at all. An identifier with no
 *   account behind it is answered from a decoy
 *   (`decoyRetryHint` in utils/login-refusal-hint.js), a keyed hash of the
 *   identifier that comes out yes about half the time. So a typo in an email
 *   address can produce a retry, and the password is then sent for an account
 *   that does not exist. That is deliberate: an honest "no" for every unknown
 *   address would turn this field into a way to discover which addresses have
 *   accounts. The cost is a password transmitted to a sign-in that cannot
 *   succeed; the alternative is a working account-enumeration oracle.
 *
 * ## What it still cannot avoid
 *
 * If `/auth/prelogin` cannot be reached there is no salt, so no value can be
 * derived and there is nothing to send but the password.
 * `firstAttemptNeedsPassword` returns true in that case and the password goes
 * in the FIRST request, not in a retry, which is why no hint can prevent it.
 *
 * Stated rather than hidden: it needs our own API to be unreachable or
 * hostile. For an account that refuses passwords the attempt then fails, so
 * it grants no access. It does not undo the disclosure: whoever answered the
 * request has the password either way, and the record holding the wrapped
 * master key holds the salt and iteration count beside it.
 */

/**
 * The server's refusal field, named here so a reader does not have to infer
 * it from a template string.
 */
export const RETRY_HINT_FIELD = "retryWithPassword";

/** Refusal statuses that mean the credential was judged and rejected. */
const CREDENTIAL_REFUSAL_STATUSES = Object.freeze([400, 401, 403]);

/**
 * The body of a sign-in request.
 *
 * `password` is spread in only when `includePassword` is true, so there is
 * exactly one place in the client where a password can enter a login body and
 * exactly one flag that puts it there.
 *
 * @param {{
 *   usernameOrEmail: string,
 *   password?: string,
 *   authHash?: string|null,
 *   captchaToken?: string,
 *   includePassword?: boolean,
 *   extra?: object,
 * }} p
 * @returns {object}
 */
export const buildLoginBody = ({
  usernameOrEmail,
  password,
  authHash = null,
  captchaToken,
  includePassword = false,
  extra = {},
}) => ({
  usernameOrEmail,
  ...(includePassword ? { password } : {}),
  ...(authHash ? { authHash } : {}),
  captchaToken,
  ...extra,
});

/**
 * Does the first attempt carry the password?
 *
 * Only when no value could be derived. Holding one is the whole reason not to
 * send a password, and it does not depend on anything remembered about this
 * browser: a second laptop, a private window and a new phone all omit it on
 * their FIRST attempt, because what decides is the account rather than
 * anything stored here.
 *
 * @param {{ authHash?: string|null }} p
 * @returns {boolean}
 */
export const firstAttemptNeedsPassword = ({ authHash = null } = {}) =>
  !authHash;

/**
 * May the client retry a refused hash-only sign-in, this time with the
 * password?
 *
 * THREE CONDITIONS, ALL REQUIRED.
 *
 * 1. There was a hash to be refused. With no hash the first attempt already
 *    carried the password and there is nothing to retry.
 * 2. The refusal judged a credential. A 429 or a 500 is not evidence that the
 *    value was wrong, and retrying those spends the rate limiter's budget for
 *    nothing.
 * 3. The server said the password could be accepted. OUR server says that
 *    only for an account that has not finished migrating: one with no stored
 *    value, or one whose stored value has gone stale.
 *
 * WHAT MIGRATING COSTS, stated plainly because it is the question this file
 * exists to answer. ONE sign-in. An account with no stored value leads with
 * nothing, so its first attempt carries the password under rule 1, or is
 * refused and retries under rule 3. Either way that single request is what
 * establishes the value, and from the next sign-in onward the account leads
 * with the derived value instead. It is one transmission, once, not one per
 * sign-in and not one per device.
 *
 * WHY RULE 3 EXISTS AT ALL. Without it the client retried on the status
 * alone, so an account created on web 1.47.0 or later, which has a stored
 * value from birth and never needs this path, transmitted its password every
 * time its owner mistyped a character. A refused hash and a wrong password
 * are the same 400.
 *
 * CONDITION 3 DESCRIBES WHAT OUR SERVER SENDS, NOT WHAT THIS FUNCTION
 * ENFORCES, and the difference is the honest limit of this file. The field is
 * supplied by whoever answered the request. A client cannot verify it: the
 * one place that could say whether an account accepts a password is
 * /auth/prelogin, and it deliberately does not, because an account with no
 * salt takes its decoy branch and the answer would then come from the
 * identifier rather than the account.
 *
 * So anything able to shape a response can ask any client for a password,
 * including an account that has fully migrated and would be refused if it
 * sent one. Do not read rule 3 as a guarantee about migrated accounts. What
 * closes this is removing the retry once no account is unmigrated, since
 * letting an unmigrated account migrate is the only thing it exists for.
 *
 * A SERVER THAT SAYS NOTHING GETS NO RETRY. An older build, or a response
 * shaped unexpectedly, leaves the field undefined and this returns false. The
 * safe direction is not transmitting, and it costs the unmigrated account
 * nothing: with no stored value there is no hash to lead with, so its first
 * attempt already carried the password under rule 1 and it migrates anyway.
 *
 * @param {{ status?: number, data?: object, hadAuthHash?: boolean }} p
 * @returns {boolean}
 */
export const mayRetryWithPassword = ({
  status,
  data = {},
  hadAuthHash = false,
} = {}) => {
  if (!hadAuthHash) {
    return false;
  }
  if (!CREDENTIAL_REFUSAL_STATUSES.includes(status)) {
    return false;
  }
  return data?.[RETRY_HINT_FIELD] === true;
};
