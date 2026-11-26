import { describe, expect, it } from 'vitest';
import {
  AUDIT_EXPORT_MAX_ROWS,
  AUDIT_PAGE_MAX,
  auditCategoryOf,
  auditCsvRow,
  auditExportFilename,
  auditFilterParams,
  auditSqlConditions,
  auditSqlCursorCondition,
  csvCell,
  decodeAuditCursor,
  encodeAuditCursor,
  matchesAuditFilters,
  parseAuditExport,
  parseAuditFilters,
  parseAuditPage,
} from './auditQuery.js';

const params = (query) => new URLSearchParams(query);
const ID = '0b6f8a52-4c1e-4f8a-9a52-3c1e4f8a9a52';
const CORRELATION = '11111111-1111-4111-8111-111111111111';

const event = (overrides = {}) => ({
  id: ID,
  eventType: 'publish.receipt.accepted',
  actorId: 'publish-worker:agent-1',
  resourceType: 'publish-request',
  resourceId: 'PUB-0042',
  correlationId: CORRELATION,
  outcome: 'success',
  severity: 'info',
  summary: 'Controlled publish completed for PUB-0042',
  metadata: { authentication: 'hmac' },
  occurredAt: '2026-11-17T10:00:00.000Z',
  tenantId: null,
  ...overrides,
});

describe('audit filters', () => {
  it('reads every filter and leaves defaults out of the query string', () => {
    const filters = parseAuditFilters(
      params(
        `category=publish&failures=true&actor=alice&resourceType=publish-request&resourceId=PUB-1&correlationId=${CORRELATION.toUpperCase()}&q=receipt&from=2026-11-01&to=2026-11-18T00:00:00Z`,
      ),
    );
    expect(filters).toEqual({
      category: 'publish',
      failuresOnly: true,
      actor: 'alice',
      resourceType: 'publish-request',
      resourceId: 'PUB-1',
      correlationId: CORRELATION,
      q: 'receipt',
      from: '2026-11-01T00:00:00.000Z',
      to: '2026-11-18T00:00:00.000Z',
    });
    expect(auditFilterParams(parseAuditFilters(params(''))).toString()).toBe('');
    expect(parseAuditFilters(params(auditFilterParams(filters).toString()))).toEqual(filters);
  });

  it.each([
    ['category=secret', /Unknown category/],
    ['failures=yes', /failures/],
    ['correlationId=not-a-uuid', /UUID/],
    ['from=yesterday', /ISO 8601/],
    ['from=2026-11-18&to=2026-11-01', /before/],
    [`q=${'x'.repeat(201)}`, /longer than 200/],
  ])('refuses %s instead of silently widening the query', (query, message) => {
    expect(() => parseAuditFilters(params(query))).toThrow(message);
  });

  it('pages with a bounded limit and a cursor it can verify', () => {
    expect(parseAuditPage(params(''))).toEqual({ limit: 100, before: null });
    expect(parseAuditPage(params('limit=5000')).limit).toBe(AUDIT_PAGE_MAX);
    expect(parseAuditPage(params('limit=0')).limit).toBe(1);
    expect(() => parseAuditPage(params('limit=ten'))).toThrow(/integer/);
    const cursor = encodeAuditCursor({ occurredMicros: '1794916000000123', id: ID });
    expect(parseAuditPage(params(`before=${cursor}`)).before).toEqual({
      occurredMicros: '1794916000000123',
      id: ID,
    });
    for (const forged of [
      '%27%3B--',
      Buffer.from(`1.${'z'.repeat(36)}`).toString('base64url'),
      'a'.repeat(101),
    ]) {
      expect(() => decodeAuditCursor(decodeURIComponent(forged))).toThrow(/Invalid cursor/);
    }
  });

  it('requires an explicit period and the csv format for an export', () => {
    expect(() => parseAuditExport(params('from=2026-11-01'))).toThrow(/both from and to/);
    expect(() => parseAuditExport(params('from=2026-11-01&to=2026-11-02&format=xlsx'))).toThrow(
      /format=csv/,
    );
    expect(parseAuditExport(params('from=2026-11-01&to=2026-11-02')).from).toBe(
      '2026-11-01T00:00:00.000Z',
    );
    expect(AUDIT_EXPORT_MAX_ROWS).toBe(50_000);
  });
});

describe('matching (memory store)', () => {
  it('applies each filter like the SQL does', () => {
    const match = (query, overrides) =>
      matchesAuditFilters(event(overrides), parseAuditFilters(params(query)));
    expect(match('category=publish')).toBe(true);
    expect(match('category=onboarding')).toBe(false);
    expect(match('category=other', { eventType: 'audit.exported' })).toBe(true);
    expect(match('failures=true')).toBe(false);
    expect(match('failures=true', { outcome: 'denied' })).toBe(true);
    expect(match('q=PUBLISH-REQUEST:pub-0042')).toBe(true);
    expect(match('q=100%25')).toBe(false);
    expect(match('from=2026-11-17T10:00:00Z')).toBe(true);
    expect(match('to=2026-11-17T10:00:00Z')).toBe(false);
    expect(match(`correlationId=${CORRELATION}`)).toBe(true);
    expect(match('actor=publish-worker')).toBe(false);
  });

  it('categorises by event-type prefix', () => {
    expect(auditCategoryOf('auth.login.success').key).toBe('signin');
    expect(auditCategoryOf('audit.exported').key).toBe('other');
  });
});

describe('SQL', () => {
  it('binds every value and escapes LIKE wildcards in the search text', () => {
    const values = [];
    const conditions = auditSqlConditions(
      parseAuditFilters(params('category=other&failures=true&q=50%25_off\\x')),
      values,
    );
    expect(conditions[0]).toBe('NOT (event_type LIKE ANY($1::text[]))');
    expect(values[0]).toEqual([
      'auth.%',
      'rbac.%',
      'remediation.%',
      'publish.%',
      'onboarding.%',
      'user.%',
    ]);
    expect(conditions[1]).toBe(`outcome <> 'success'`);
    expect(values[1]).toBe('%50\\%\\_off\\\\x%');
    expect(conditions.join(' ')).not.toContain('50%');
  });

  it('pages on (occurred_at, id) with an exact microsecond boundary', () => {
    const values = ['x'];
    expect(auditSqlCursorCondition({ occurredMicros: '1794916000000123', id: ID }, values)).toBe(
      `(occurred_at, id) < ((timestamptz 'epoch' + $2::bigint * interval '1 microsecond'), $3::uuid)`,
    );
    expect(values).toEqual(['x', '1794916000000123', ID]);
    expect(auditSqlCursorCondition(null, values)).toBeNull();
  });
});

describe('CSV', () => {
  it('quotes per RFC 4180 and never lets a cell run as a formula', () => {
    expect(csvCell('plain')).toBe('plain');
    expect(csvCell('a,b')).toBe('"a,b"');
    expect(csvCell('say "hi"\nbye')).toBe('"say ""hi""\nbye"');
    expect(csvCell('=HYPERLINK("http://x")')).toBe(`"'=HYPERLINK(""http://x"")"`);
    for (const start of ['+1', '-1', '@SUM(A1)', '\tx'])
      expect(csvCell(start).replace(/^"/, '')).toMatch(/^'/);
    expect(csvCell(null)).toBe('');
  });

  it('writes one CRLF-terminated row per event with its metadata', () => {
    const row = auditCsvRow(event());
    expect(row.endsWith('\r\n')).toBe(true);
    expect(row).toContain(',Publish,');
    expect(row).toContain('publish-request:PUB-0042');
    expect(row).toContain('"{""authentication"":""hmac""}"');
    expect(
      auditExportFilename({ from: '2026-11-01T00:00:00.000Z', to: '2026-11-18T00:00:00.000Z' }),
    ).toBe('ssi-audit-20261101-20261118.csv');
  });
});
