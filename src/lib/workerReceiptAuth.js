import { createHash, timingSafeEqual } from 'node:crypto';
import {
  verifyWorkerEvidenceRequest,
  WorkerEvidenceAuthenticationError,
} from './workerEvidenceAuth.js';

// SSI — Authentication of the receipts the publish and onboarding workers send back
// (POST /publish-requests/{id}/receipt, POST /onboarding/{id}/import-receipt).
//
// A receipt is signed like every other worker channel (workerEvidenceAuth.js): HMAC-SHA256
// over its purpose, timestamp, request ID, worker ID and the SHA-256 of its exact body, so it
// cannot be altered, moved to another request or channel, or replayed after the age limit.
//
// Migration: while the legacy bearer token is still configured, an unsigned receipt that
// carries it is accepted and reported as such (audit metadata, server log). Removing the
// token from the environment ends the migration without a code change. A receipt that
// carries a signature is never downgraded: the signature alone decides.

export const RECEIPT_AUTHENTICATION = Object.freeze({
  HMAC: 'hmac',
  LEGACY_TOKEN: 'legacy-token',
});

const SIGNATURE_HEADER = 'x-ssi-evidence-signature';

function headerValue(headers, name) {
  const key = Object.keys(headers || {}).find((candidate) => candidate.toLowerCase() === name);
  const value = key ? headers[key] : '';
  return String(Array.isArray(value) ? value[0] : value || '').trim();
}

// Constant time and independent of the length of the received value.
function tokenMatches(expected, received) {
  const digest = (value) => createHash('sha256').update(String(value), 'utf8').digest();
  return (
    Boolean(expected) && Boolean(received) && timingSafeEqual(digest(expected), digest(received))
  );
}

/**
 * Authenticates a worker receipt before it is read into the request's state.
 *
 * @param {object} options
 * @param {string} options.label            "Publish receipt" or "Onboarding receipt" (error messages)
 * @param {string} options.subject          the request ID from the URL; the signature is bound to it
 * @param {string} options.rawBody          the exact request body that was signed
 * @param {object} options.headers          the request headers
 * @param {string} options.purpose          EVIDENCE_PURPOSE.PUBLISH_RECEIPT or ONBOARD_RECEIPT
 * @param {string} [options.hmacSecret]     the channel's HMAC secret (at least 32 bytes)
 * @param {string} [options.legacyToken]    the migration-period bearer token, when still configured
 * @param {string} options.legacyTokenHeader the header that carries the legacy token (lower case)
 * @returns {{ method: string, workerId: string | null }}
 */
export function authenticateWorkerReceipt({
  label,
  subject,
  rawBody,
  headers,
  purpose,
  hmacSecret,
  legacyToken,
  legacyTokenHeader,
  now = Date.now(),
  maxAgeSeconds = 300,
}) {
  const secret = String(hmacSecret || '');
  const token = String(legacyToken || '');

  if (headerValue(headers, SIGNATURE_HEADER)) {
    if (!secret) {
      throw new WorkerEvidenceAuthenticationError(
        503,
        `${label} signature verification is not configured`,
      );
    }
    const { workerId } = verifyWorkerEvidenceRequest({
      jobId: subject,
      rawBody,
      headers,
      secret,
      now,
      maxAgeSeconds,
      purpose,
    });
    return { method: RECEIPT_AUTHENTICATION.HMAC, workerId };
  }

  if (token) {
    if (!tokenMatches(token, headerValue(headers, legacyTokenHeader))) {
      throw new WorkerEvidenceAuthenticationError(403, `${label} authentication failed`);
    }
    return { method: RECEIPT_AUTHENTICATION.LEGACY_TOKEN, workerId: null };
  }

  if (secret) {
    throw new WorkerEvidenceAuthenticationError(
      401,
      `${label} authentication failed: a signed receipt is required`,
    );
  }
  throw new WorkerEvidenceAuthenticationError(503, `${label} authentication is not configured`);
}

// A signed receipt names the worker that signed it; a different workerId in the body would
// let the audit trail attribute the write to a worker that never sent it.
export function assertReceiptSigner(authentication, receipt) {
  if (authentication?.method !== RECEIPT_AUTHENTICATION.HMAC) return;
  if (String(receipt?.workerId ?? '') !== authentication.workerId) {
    throw new WorkerEvidenceAuthenticationError(
      401,
      'The receipt workerId does not match the signing worker',
    );
  }
}

// The start-up line for one receipt channel: what it accepts, so an operator sees whether
// the migration is still open. null when there is nothing to report.
export function describeReceiptAuthentication({
  label,
  hmacVariable,
  tokenVariable,
  hmacSecret,
  legacyToken,
}) {
  const signed = Boolean(String(hmacSecret || ''));
  const legacy = Boolean(String(legacyToken || ''));
  if (signed && legacy) {
    return {
      level: 'warn',
      message: `${label}s: signed and, during the migration, unsigned with ${tokenVariable}. Remove ${tokenVariable} once the worker signs its receipts.`,
    };
  }
  if (legacy) {
    return {
      level: 'warn',
      message: `${label}s are accepted with ${tokenVariable} only. Set ${hmacVariable} on the server and the worker to sign them.`,
    };
  }
  if (!signed) {
    return { level: 'warn', message: `${label}s are refused (503): set ${hmacVariable}.` };
  }
  return null;
}
