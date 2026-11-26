import { describe, expect, it } from 'vitest';
import { createWorkerEvidenceHeaders, EVIDENCE_PURPOSE } from './workerEvidenceAuth.js';
import {
  assertReceiptSigner,
  authenticateWorkerReceipt,
  describeReceiptAuthentication,
  RECEIPT_AUTHENTICATION,
} from './workerReceiptAuth.js';

// Test-only values, built so no scanner mistakes them for credentials.
const SECRET = 'publish-receipt-test-'.padEnd(48, '0');
const TOKEN = 'legacy-publish-receipt-token-000000';
const NOW = Date.parse('2026-11-17T12:00:00Z');
const BODY = JSON.stringify({
  requestId: 'PUB-0042',
  status: 'published',
  workerId: 'agent-1:build-01',
});

const sign = ({
  subject = 'PUB-0042',
  body = BODY,
  secret = SECRET,
  purpose = EVIDENCE_PURPOSE.PUBLISH_RECEIPT,
  timestamp = Math.floor(NOW / 1000),
} = {}) =>
  createWorkerEvidenceHeaders({
    jobId: subject,
    rawBody: body,
    secret,
    workerId: 'agent-1:build-01',
    purpose,
    timestamp,
  });

const authenticate = (overrides = {}) =>
  authenticateWorkerReceipt({
    label: 'Publish receipt',
    subject: 'PUB-0042',
    rawBody: BODY,
    headers: {},
    purpose: EVIDENCE_PURPOSE.PUBLISH_RECEIPT,
    hmacSecret: SECRET,
    legacyToken: '',
    legacyTokenHeader: 'x-ssi-publish-receipt-token',
    now: NOW,
    ...overrides,
  });

const statusOf = (run) => {
  try {
    run();
  } catch (error) {
    return error.statusCode;
  }
  return 'accepted';
};

describe('authenticateWorkerReceipt', () => {
  it('accepts a receipt signed for this request and channel and names its worker', () => {
    expect(authenticate({ headers: sign() })).toEqual({
      method: RECEIPT_AUTHENTICATION.HMAC,
      workerId: 'agent-1:build-01',
    });
  });

  it('refuses a signature that is wrong, stale, altered or meant for something else', () => {
    expect(statusOf(() => authenticate({ headers: sign({ secret: `${SECRET}-other` }) }))).toBe(
      401,
    );
    expect(statusOf(() => authenticate({ headers: sign({ subject: 'PUB-0043' }) }))).toBe(401);
    expect(
      statusOf(() =>
        authenticate({ headers: sign({ purpose: EVIDENCE_PURPOSE.ONBOARD_RECEIPT }) }),
      ),
    ).toBe(401);
    expect(
      statusOf(() =>
        authenticate({ headers: sign({ body: BODY.replace('published', 'failed') }) }),
      ),
    ).toBe(401);
    expect(
      statusOf(() => authenticate({ headers: sign({ timestamp: Math.floor(NOW / 1000) - 301 }) })),
    ).toBe(401);
  });

  it('never lets a legacy token rescue a bad signature', () => {
    const headers = {
      ...sign({ secret: `${SECRET}-other` }),
      'X-SSI-Publish-Receipt-Token': TOKEN,
    };
    expect(statusOf(() => authenticate({ headers, legacyToken: TOKEN }))).toBe(401);
  });

  it('accepts the legacy token only while it is configured (migration)', () => {
    const headers = { 'X-SSI-Publish-Receipt-Token': TOKEN };
    expect(authenticate({ headers, legacyToken: TOKEN })).toEqual({
      method: RECEIPT_AUTHENTICATION.LEGACY_TOKEN,
      workerId: null,
    });
    expect(
      statusOf(() =>
        authenticate({ headers: { 'X-SSI-Publish-Receipt-Token': 'wrong' }, legacyToken: TOKEN }),
      ),
    ).toBe(403);
    expect(statusOf(() => authenticate({ headers, legacyToken: '' }))).toBe(401);
  });

  it('answers 503 when the channel has no way to authenticate', () => {
    expect(statusOf(() => authenticate({ hmacSecret: '', legacyToken: '' }))).toBe(503);
    expect(
      statusOf(() => authenticate({ headers: sign(), hmacSecret: '', legacyToken: TOKEN })),
    ).toBe(503);
    expect(statusOf(() => authenticate({ headers: sign(), hmacSecret: 'too-short' }))).toBe(503);
  });
});

describe('assertReceiptSigner', () => {
  const signed = { method: RECEIPT_AUTHENTICATION.HMAC, workerId: 'agent-1:build-01' };

  it('requires the receipt to name the worker that signed it', () => {
    expect(() => assertReceiptSigner(signed, { workerId: 'agent-1:build-01' })).not.toThrow();
    expect(statusOf(() => assertReceiptSigner(signed, { workerId: 'someone-else' }))).toBe(401);
    expect(statusOf(() => assertReceiptSigner(signed, {}))).toBe(401);
  });

  it('has nothing to compare for a legacy receipt', () => {
    expect(() =>
      assertReceiptSigner(
        { method: RECEIPT_AUTHENTICATION.LEGACY_TOKEN, workerId: null },
        { workerId: 'x' },
      ),
    ).not.toThrow();
  });
});

describe('describeReceiptAuthentication', () => {
  const channel = {
    label: 'Publish receipt',
    hmacVariable: 'SSI_PUBLISH_RECEIPT_HMAC_SECRET',
    tokenVariable: 'SSI_PUBLISH_RECEIPT_TOKEN',
  };

  it('is silent once only signed receipts are accepted', () => {
    expect(describeReceiptAuthentication({ ...channel, hmacSecret: SECRET })).toBeNull();
  });

  it('reports an open migration, a legacy-only channel and a closed channel', () => {
    expect(
      describeReceiptAuthentication({ ...channel, hmacSecret: SECRET, legacyToken: TOKEN }).message,
    ).toMatch(/Remove SSI_PUBLISH_RECEIPT_TOKEN/);
    expect(describeReceiptAuthentication({ ...channel, legacyToken: TOKEN }).message).toMatch(
      /Set SSI_PUBLISH_RECEIPT_HMAC_SECRET/,
    );
    expect(describeReceiptAuthentication(channel).message).toMatch(/refused \(503\)/);
  });

  it('never prints a secret or token value', () => {
    const message = describeReceiptAuthentication({
      ...channel,
      hmacSecret: SECRET,
      legacyToken: TOKEN,
    }).message;
    expect(message).not.toContain(SECRET);
    expect(message).not.toContain(TOKEN);
  });
});
