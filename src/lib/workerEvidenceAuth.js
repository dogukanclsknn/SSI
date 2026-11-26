import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

const contractVersion = 'v1';

// Domain separation: each worker channel signs a different first payload line, so a
// signature produced for one evidence type can never be replayed against another.
export const EVIDENCE_PURPOSE = Object.freeze({
  REMEDIATION: 'ssi-remediation-evidence-v1',
  SUPPLY_CHAIN: 'ssi-supply-chain-evidence-v1',
  CANDIDATE_TEST: 'ssi-candidate-test-evidence-v1',
  IMAGE_INSPECTION: 'ssi-image-inspection-evidence-v1',
  CANONICAL_REPORT: 'ssi-canonical-report-v1',
  PUBLISH_RECEIPT: 'ssi-publish-receipt-v1',
  ONBOARD_RECEIPT: 'ssi-onboard-receipt-v1',
  OS_TEMPLATE: 'ssi-os-template-evidence-v1',
});
const minimumSecretBytes = 32;
const workerIdPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export class WorkerEvidenceAuthenticationError extends Error {
  constructor(statusCode, message) {
    super(message);
    this.name = 'WorkerEvidenceAuthenticationError';
    this.statusCode = statusCode;
  }
}

function headerValue(headers, name) {
  if (typeof headers?.get === 'function') return String(headers.get(name) || '').trim();

  const expected = name.toLowerCase();
  const key = Object.keys(headers || {}).find((candidate) => candidate.toLowerCase() === expected);
  const value = key ? headers[key] : '';
  return String(Array.isArray(value) ? value[0] : value || '').trim();
}

function secureEqual(left, right) {
  const leftBuffer = Buffer.from(String(left || ''), 'utf8');
  const rightBuffer = Buffer.from(String(right || ''), 'utf8');
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function requireSigningSecret(secret) {
  const normalized = String(secret || '');
  if (Buffer.byteLength(normalized, 'utf8') < minimumSecretBytes) {
    throw new WorkerEvidenceAuthenticationError(
      503,
      `Worker evidence authentication requires a secret of at least ${minimumSecretBytes} bytes`,
    );
  }
  return normalized;
}

export function sha256ContentDigest(rawBody) {
  return `sha256:${createHash('sha256').update(rawBody).digest('hex')}`;
}

export function workerEvidenceSigningPayload({
  timestamp,
  jobId,
  workerId,
  contentDigest,
  purpose = EVIDENCE_PURPOSE.REMEDIATION,
}) {
  return [purpose, timestamp, jobId, workerId, contentDigest].join('\n');
}

export function createWorkerEvidenceHeaders({
  jobId,
  rawBody,
  secret,
  workerId,
  timestamp = Math.floor(Date.now() / 1000),
  purpose = EVIDENCE_PURPOSE.REMEDIATION,
}) {
  const signingSecret = requireSigningSecret(secret);
  const contentDigest = sha256ContentDigest(rawBody);
  const payload = workerEvidenceSigningPayload({ timestamp, jobId, workerId, contentDigest, purpose });
  const signature = createHmac('sha256', signingSecret).update(payload).digest('hex');

  return {
    'X-SSI-Evidence-Version': contractVersion,
    'X-SSI-Evidence-Timestamp': String(timestamp),
    'X-SSI-Evidence-Content-SHA256': contentDigest,
    'X-SSI-Evidence-Worker-ID': workerId,
    'X-SSI-Evidence-Signature': `sha256=${signature}`,
  };
}

export function verifyWorkerEvidenceRequest({
  jobId,
  rawBody,
  headers,
  secret,
  now = Date.now(),
  maxAgeSeconds = 300,
  maxFutureSkewSeconds = 30,
  purpose = EVIDENCE_PURPOSE.REMEDIATION,
}) {
  const signingSecret = requireSigningSecret(secret);
  const version = headerValue(headers, 'x-ssi-evidence-version');
  const timestampText = headerValue(headers, 'x-ssi-evidence-timestamp');
  const suppliedDigest = headerValue(headers, 'x-ssi-evidence-content-sha256').toLowerCase();
  const workerId = headerValue(headers, 'x-ssi-evidence-worker-id');
  const suppliedSignature = headerValue(headers, 'x-ssi-evidence-signature').toLowerCase();
  const timestamp = Number(timestampText);
  const nowSeconds = Math.floor(Number(now) / 1000);

  if (version !== contractVersion || !Number.isSafeInteger(timestamp) || !workerIdPattern.test(workerId)) {
    throw new WorkerEvidenceAuthenticationError(401, 'Worker evidence authentication failed');
  }
  if (timestamp < nowSeconds - maxAgeSeconds || timestamp > nowSeconds + maxFutureSkewSeconds) {
    throw new WorkerEvidenceAuthenticationError(401, 'Worker evidence authentication failed');
  }

  const contentDigest = sha256ContentDigest(rawBody);
  if (!secureEqual(contentDigest, suppliedDigest)) {
    throw new WorkerEvidenceAuthenticationError(401, 'Worker evidence authentication failed');
  }

  const payload = workerEvidenceSigningPayload({ timestamp, jobId, workerId, contentDigest, purpose });
  const expectedSignature = `sha256=${createHmac('sha256', signingSecret).update(payload).digest('hex')}`;
  if (!secureEqual(expectedSignature, suppliedSignature)) {
    throw new WorkerEvidenceAuthenticationError(401, 'Worker evidence authentication failed');
  }

  return { contentDigest, timestamp, version, workerId };
}
