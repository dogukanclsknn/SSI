import { describe, expect, it } from 'vitest';
import {
  applyExceptions,
  buildExceptionAdjustment,
  buildExceptionPolicyConfig,
  createExceptionRecord,
  decideException,
  effectiveExceptionStatus,
  ExceptionValidationError,
  exceptionScopesOverlap,
  isExceptionActive,
  isExceptionOpen,
  repositoryFromReference,
  severityForScope,
  validateExceptionRequest,
} from './policyExceptions.js';

const NOW = '2026-10-14T10:00:00.000Z';
const DAY = 24 * 60 * 60 * 1000;
const inDays = (days) => new Date(Date.parse(NOW) + days * DAY).toISOString();
const config = buildExceptionPolicyConfig({});

function request(overrides = {}) {
  return {
    cve: 'CVE-2023-45853',
    repository: 'ssi-images/onboarded/nginx',
    package: 'zlib1g',
    reasonCode: 'no_fix_available',
    justification: 'Debian 12 will not fix this; minizip is not linked by nginx.',
    expiresAt: inDays(30),
    ...overrides,
  };
}

function approvedException(overrides = {}) {
  const record = createExceptionRecord({
    id: 'EXC-0001',
    request: validateExceptionRequest(request(), { config, severity: 'critical', now: NOW }),
    actorId: 'alex.morgan',
    now: NOW,
  });
  return {
    ...decideException(record, {
      decision: 'approve',
      actorId: 'sam.lee',
      note: 'Verified: not reachable.',
      now: NOW,
    }),
    ...overrides,
  };
}

describe('risk acceptance — configuration and references', () => {
  it('defaults to 90 days, 30 days for critical, and caps critical at the general limit', () => {
    expect(config).toMatchObject({ maxDays: 90, maxDaysCritical: 30, twoPersonRule: true });
    expect(
      buildExceptionPolicyConfig({
        SSI_EXCEPTION_MAX_DAYS: '20',
        SSI_EXCEPTION_MAX_DAYS_CRITICAL: '45',
      }),
    ).toMatchObject({
      maxDays: 20,
      maxDaysCritical: 20,
    });
  });

  it('reduces image references to project/repository', () => {
    expect(
      repositoryFromReference('registry.example.com/ssi-images/onboarded/nginx:1.27'),
    ).toBe('ssi-images/onboarded/nginx');
    expect(
      repositoryFromReference(`ssi-images/onboarded/nginx@sha256:${'a'.repeat(64)}`),
    ).toBe('ssi-images/onboarded/nginx');
    expect(repositoryFromReference('localhost:5000/team/app:1')).toBe('team/app');
  });

  it('reads the highest severity of a CVE from the repository scans', () => {
    const reports = [
      {
        image: 'ssi-images/onboarded/nginx:1.27',
        findings: [{ cve: 'CVE-2023-45853', package: 'zlib1g', severity: 'High' }],
      },
      {
        image: 'ssi-images/onboarded/nginx:1.26',
        findings: [{ cve: 'CVE-2023-45853', package: 'zlib1g', severity: 'Critical' }],
      },
      {
        image: 'ssi-images/other/app:1',
        findings: [{ cve: 'CVE-2023-45853', package: 'zlib1g', severity: 'Low' }],
      },
    ];
    expect(
      severityForScope(reports, {
        cve: 'cve-2023-45853',
        repository: 'ssi-images/onboarded/nginx',
      }),
    ).toBe('critical');
    expect(
      severityForScope(reports, {
        cve: 'CVE-2099-0001',
        repository: 'ssi-images/onboarded/nginx',
      }),
    ).toBe('');
  });
});

describe('risk acceptance — request validation', () => {
  it('normalizes a valid request', () => {
    const result = validateExceptionRequest(request({ cve: 'cve-2023-45853' }), {
      config,
      severity: 'Critical',
      now: NOW,
    });
    expect(result).toMatchObject({
      cve: 'CVE-2023-45853',
      severity: 'critical',
      severityVerified: true,
      digest: null,
    });
  });

  it.each([
    [{ cve: 'not-a-cve' }, /valid CVE/],
    [{ repository: 'nginx' }, /project\/repository/],
    [{ reasonCode: 'because' }, /Reason must be/],
    [{ justification: 'too short' }, /at least 20/],
    [{ digest: 'sha256:abc' }, /full sha256/],
    [{ expiresAt: inDays(-1) }, /future date/],
  ])('rejects %o', (overrides, message) => {
    expect(() =>
      validateExceptionRequest(request(overrides), { config, severity: 'high', now: NOW }),
    ).toThrow(message);
  });

  it('limits critical findings to 30 days and others to 90 days', () => {
    expect(() =>
      validateExceptionRequest(request({ expiresAt: inDays(31) }), {
        config,
        severity: 'critical',
        now: NOW,
      }),
    ).toThrow(/at most 30 days/);
    expect(
      validateExceptionRequest(request({ expiresAt: inDays(90) }), {
        config,
        severity: 'high',
        now: NOW,
      }).expiresAt,
    ).toBe(inDays(90));
  });

  it('applies the critical limit when the scans cannot confirm the severity (fail-closed)', () => {
    expect(() =>
      validateExceptionRequest(request({ expiresAt: inDays(60) }), {
        config,
        severity: '',
        now: NOW,
      }),
    ).toThrow(/Critical limit applies: at most 30 days/);
    expect(validateExceptionRequest(request(), { config, severity: '', now: NOW })).toMatchObject({
      severity: 'unknown',
      severityVerified: false,
    });
  });
});

describe('risk acceptance — lifecycle', () => {
  const requested = () =>
    createExceptionRecord({
      id: 'EXC-0001',
      request: validateExceptionRequest(request(), { config, severity: 'critical', now: NOW }),
      actorId: 'alex.morgan',
      now: NOW,
    });

  it('enforces the two-person rule', () => {
    expect(() =>
      decideException(requested(), {
        decision: 'approve',
        actorId: 'Alex.Morgan',
        note: 'Self approval attempt',
        now: NOW,
      }),
    ).toThrow(/Two-person rule/);
  });

  it('requires a decision note', () => {
    expect(() =>
      decideException(requested(), {
        decision: 'reject',
        actorId: 'sam.lee',
        note: 'no',
        now: NOW,
      }),
    ).toThrow(/at least 10/);
  });

  it('approves, records history and becomes Expired after expiresAt without a stored state change', () => {
    const approved = approvedException();
    expect(approved).toMatchObject({ status: 'Approved', decidedBy: 'sam.lee' });
    expect(approved.history.map((item) => item.action)).toEqual(['requested', 'approved']);
    expect(isExceptionActive(approved, NOW)).toBe(true);
    expect(effectiveExceptionStatus(approved, inDays(31))).toBe('Expired');
    expect(isExceptionActive(approved, inDays(31))).toBe(false);
  });

  it('only revokes active exceptions and only decides requested ones', () => {
    const approved = approvedException();
    const revoked = decideException(approved, {
      decision: 'revoke',
      actorId: 'sam.lee',
      note: 'Base image upgraded.',
      now: NOW,
    });
    expect(revoked.status).toBe('Revoked');
    expect(() =>
      decideException(revoked, {
        decision: 'revoke',
        actorId: 'sam.lee',
        note: 'Again, please.',
        now: NOW,
      }),
    ).toThrow(ExceptionValidationError);
    expect(() =>
      decideException(approved, {
        decision: 'approve',
        actorId: 'other.user',
        note: 'Approve twice?',
        now: NOW,
      }),
    ).toThrow(/Only a requested exception/);
    expect(() =>
      decideException(approved, {
        decision: 'revoke',
        actorId: 'sam.lee',
        note: 'Too late to revoke.',
        now: inDays(40),
      }),
    ).toThrow(/is Expired/);
  });

  it('detects overlapping scopes', () => {
    const base = { cve: 'CVE-2023-45853', repository: 'a/b', package: null, digest: null };
    expect(exceptionScopesOverlap(base, { ...base, package: 'zlib1g' })).toBe(true);
    expect(
      exceptionScopesOverlap({ ...base, package: 'zlib1g' }, { ...base, package: 'libz' }),
    ).toBe(false);
    expect(exceptionScopesOverlap(base, { ...base, repository: 'a/c' })).toBe(false);
  });
});

describe('risk acceptance — applyExceptions', () => {
  const findings = [
    { cve: 'CVE-2023-45853', package: 'zlib1g', severity: 'Critical' },
    { cve: 'CVE-2023-6879', package: 'libaom3', severity: 'Critical' },
    { cve: 'CVE-2023-52425', package: 'libexpat1', severity: 'High' },
  ];
  const repositories = ['registry.example.com/ssi-images/onboarded/nginx:1.27'];

  it('accepts only matching findings of active exceptions', () => {
    const result = applyExceptions({
      findings,
      exceptions: [approvedException()],
      repositories,
      digests: [],
      now: NOW,
    });
    expect(result.accepted).toEqual([
      { cve: 'CVE-2023-45853', package: 'zlib1g', severity: 'critical', exceptionId: 'EXC-0001' },
    ]);
    expect(result.remaining).toMatchObject({ critical: 1, high: 1 });
    expect(result.appliedExceptions).toEqual([
      { id: 'EXC-0001', cve: 'CVE-2023-45853', expiresAt: inDays(30), findings: 1 },
    ]);
  });

  it('ignores expired, other-repository, other-package and other-digest exceptions', () => {
    const cases = [
      { exceptions: [approvedException()], now: inDays(31) },
      {
        exceptions: [approvedException({ repository: 'ssi-images/onboarded/other' })],
        now: NOW,
      },
      { exceptions: [approvedException({ package: 'libz1' })], now: NOW },
      { exceptions: [approvedException({ digest: `sha256:${'c'.repeat(64)}` })], now: NOW },
      { exceptions: [{ ...approvedException(), status: 'Requested' }], now: NOW },
    ];
    for (const item of cases) {
      const result = applyExceptions({
        findings,
        repositories,
        digests: [`sha256:${'d'.repeat(64)}`],
        ...item,
      });
      expect(result.accepted).toEqual([]);
      expect(result.remaining).toMatchObject({ critical: 2, high: 1 });
    }
  });
});

describe('risk acceptance — buildExceptionAdjustment', () => {
  const OUT = `sha256:${'a'.repeat(64)}`;
  const SRC = `sha256:${'b'.repeat(64)}`;
  const job = (severity = { critical: 1, high: 0 }) => ({
    image: 'ssi-images/onboarded/nginx:1.27',
    sourceDigest: SRC,
    patchedImageDigest: OUT,
    patchedImageTag:
      'registry.example.com/ssi-images/approved/onboarded-nginx:verified-1',
    fullImageComparison: { output: { severity } },
  });
  const reports = [
    {
      image: 'ssi-images/approved/onboarded-nginx:verified-1',
      digest: OUT,
      findings: [{ cve: 'CVE-2023-45853', package: 'zlib1g', severity: 'Critical' }],
    },
    { image: 'ssi-images/onboarded/nginx:1.27', digest: SRC, findings: [] },
  ];

  it('returns none without active exceptions', () => {
    expect(buildExceptionAdjustment({ job: job(), reports, exceptions: [], now: NOW })).toEqual({
      status: 'none',
    });
  });

  it('applies an exception from the source repository to the remediated output', () => {
    const result = buildExceptionAdjustment({
      job: job(),
      reports,
      exceptions: [approvedException()],
      now: NOW,
    });
    expect(result.status).toBe('applied');
    expect(result.appliedExceptions.map((item) => item.id)).toEqual(['EXC-0001']);
  });

  it('is unavailable when the output report is missing or changed since verification', () => {
    expect(
      buildExceptionAdjustment({
        job: job(),
        reports: reports.slice(1),
        exceptions: [approvedException()],
        now: NOW,
      }).status,
    ).toBe('unavailable');
    expect(
      buildExceptionAdjustment({
        job: job({ critical: 2, high: 0 }),
        reports,
        exceptions: [approvedException()],
        now: NOW,
      }),
    ).toMatchObject({ status: 'unavailable', reason: expect.stringMatching(/changed since/) });
  });
});

describe('risk acceptance — review hardening', () => {
  const repositories = ['ssi-images/onboarded/nginx'];

  it('stores GHSA ids with their canonical lower-case body', () => {
    const result = validateExceptionRequest(request({ cve: 'ghsa-JFH8-c2jp-5V3Q' }), {
      config,
      severity: 'high',
      now: NOW,
    });
    expect(result.cve).toBe('GHSA-jfh8-c2jp-5v3q');
  });

  it('computes the expiry from durationDays on the server clock', () => {
    const result = validateExceptionRequest(request({ expiresAt: undefined, durationDays: 30 }), {
      config,
      severity: 'critical',
      now: NOW,
    });
    expect(result.expiresAt).toBe(inDays(30));
    expect(() =>
      validateExceptionRequest(request({ durationDays: 1.5 }), {
        config,
        severity: 'high',
        now: NOW,
      }),
    ).toThrow(/whole number/);
  });

  it('does not cover a finding rated above the approved severity', () => {
    const high = approvedException({ severity: 'high', severityVerified: true });
    const findings = [{ cve: 'CVE-2023-45853', package: 'zlib1g', severity: 'Critical' }];
    expect(
      applyExceptions({ findings, exceptions: [high], repositories, digests: [], now: NOW })
        .accepted,
    ).toEqual([]);
    const unverified = approvedException({ severity: 'unknown', severityVerified: false });
    expect(
      applyExceptions({ findings, exceptions: [unverified], repositories, digests: [], now: NOW })
        .accepted,
    ).toHaveLength(1);
  });

  it('only accepts gated (Critical/High) findings', () => {
    const findings = [{ cve: 'CVE-2023-45853', package: 'zlib1g', severity: 'Medium' }];
    const result = applyExceptions({
      findings,
      exceptions: [approvedException()],
      repositories,
      digests: [],
      now: NOW,
    });
    expect(result.accepted).toEqual([]);
    expect(result.appliedExceptions).toEqual([]);
    expect(result.remaining.medium).toBe(1);
  });

  it('matches a digest-bound exception against the source digest of the remediation', () => {
    const source = `sha256:${'e'.repeat(64)}`;
    const findings = [{ cve: 'CVE-2023-45853', package: 'zlib1g', severity: 'Critical' }];
    const bound = approvedException({ digest: source });
    expect(
      applyExceptions({
        findings,
        exceptions: [bound],
        repositories,
        digests: [`sha256:${'f'.repeat(64)}`, source],
        now: NOW,
      }).accepted,
    ).toHaveLength(1);
  });

  it('does not let a stale request block a new one', () => {
    const stale = { status: 'Requested', expiresAt: inDays(-1) };
    expect(isExceptionOpen(stale, NOW)).toBe(false);
    expect(isExceptionOpen({ status: 'Requested', expiresAt: inDays(5) }, NOW)).toBe(true);
  });
});
