// SSI — Querying the audit log (GET /audit-events, /audit-events/summary, /audit-events/export).
//
// One definition of what a filter means, used by both stores (PostgreSQL builds SQL from it,
// the memory store applies the same predicate) and by the Audit screen. Pages are read with a
// keyset cursor on (occurredAt, id) — newest first — so events recorded while someone pages
// through the log never shift, repeat or hide a row. Pure: no I/O.

export class AuditQueryError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AuditQueryError';
    this.statusCode = 400;
  }
}

// The Audit screen's categories. "other" is everything no prefix claims.
export const AUDIT_CATEGORIES = Object.freeze([
  { key: 'all', label: 'All' },
  { key: 'signin', label: 'Sign-in', prefix: 'auth.' },
  { key: 'access', label: 'Access', prefix: 'rbac.' },
  { key: 'remediation', label: 'Remediation', prefix: 'remediation.' },
  { key: 'publish', label: 'Publish', prefix: 'publish.' },
  { key: 'onboarding', label: 'Onboarding', prefix: 'onboarding.' },
  { key: 'users', label: 'Users', prefix: 'user.' },
]);
export const AUDIT_OTHER_CATEGORY = Object.freeze({ key: 'other', label: 'Other' });
const PREFIXED = AUDIT_CATEGORIES.filter((category) => category.prefix);
const CATEGORY_KEYS = new Set([
  ...AUDIT_CATEGORIES.map((category) => category.key),
  AUDIT_OTHER_CATEGORY.key,
]);

export const AUDIT_PAGE_DEFAULT = 100;
export const AUDIT_PAGE_MAX = 250;
// The most rows one CSV export may hold; a wider request is refused before anything is sent.
export const AUDIT_EXPORT_MAX_ROWS = 50_000;

const TEXT_MAX = 200;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CURSOR = /^(\d{1,17})\.([0-9a-f-]{36})$/i;

export function auditCategoryOf(eventType) {
  const type = String(eventType || '');
  return PREFIXED.find((category) => type.startsWith(category.prefix)) || AUDIT_OTHER_CATEGORY;
}

// ── Cursor ─────────────────────────────────────────────────────────────────────
// Opaque to clients: base64url of "<epoch microseconds>.<event id>". Microseconds, so a row
// written with sub-millisecond precision is still compared exactly.
export function encodeAuditCursor({ occurredMicros, id }) {
  return Buffer.from(`${occurredMicros}.${id}`, 'utf8').toString('base64url');
}

export function decodeAuditCursor(value) {
  const text = String(value || '');
  if (!text) return null;
  if (text.length > 100 || !/^[A-Za-z0-9_-]+$/.test(text))
    throw new AuditQueryError('Invalid cursor');
  const match = Buffer.from(text, 'base64url').toString('utf8').match(CURSOR);
  if (!match || !UUID.test(match[2])) throw new AuditQueryError('Invalid cursor');
  return { occurredMicros: match[1], id: match[2].toLowerCase() };
}

// Epoch microseconds (as a decimal string) of an ISO timestamp held to millisecond precision.
export function micros(isoTimestamp) {
  const ms = Date.parse(isoTimestamp);
  return Number.isFinite(ms) ? String(BigInt(ms) * 1000n) : '0';
}

// ── Parameters ─────────────────────────────────────────────────────────────────
function textParam(params, name) {
  const value = String(params.get(name) ?? '').trim();
  if (value.length > TEXT_MAX)
    throw new AuditQueryError(`${name} is longer than ${TEXT_MAX} characters`);
  return value;
}

function timeParam(params, name) {
  const value = String(params.get(name) ?? '').trim();
  if (!value) return '';
  // An ISO 8601 date or date-time; anything Date.parse would guess at is refused.
  if (
    !/^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:\d{2}))?$/.test(
      value,
    )
  ) {
    throw new AuditQueryError(`${name} must be an ISO 8601 date or date-time`);
  }
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) throw new AuditQueryError(`${name} is not a valid date`);
  return new Date(ms).toISOString();
}

// The filters of a request (URLSearchParams). Unknown values are refused, never ignored, so a
// typo cannot silently widen an audit query or an export.
export function parseAuditFilters(params) {
  const category = String(params.get('category') ?? 'all').trim() || 'all';
  if (!CATEGORY_KEYS.has(category)) throw new AuditQueryError('Unknown category');

  const failures = String(params.get('failures') ?? '')
    .trim()
    .toLowerCase();
  if (!['', 'true', 'false'].includes(failures))
    throw new AuditQueryError('failures must be true or false');

  const correlationId = textParam(params, 'correlationId').toLowerCase();
  if (correlationId && !UUID.test(correlationId))
    throw new AuditQueryError('correlationId must be a UUID');

  const from = timeParam(params, 'from');
  const to = timeParam(params, 'to');
  if (from && to && Date.parse(from) >= Date.parse(to))
    throw new AuditQueryError('from must be before to');

  return {
    category,
    failuresOnly: failures === 'true',
    actor: textParam(params, 'actor'),
    resourceType: textParam(params, 'resourceType'),
    resourceId: textParam(params, 'resourceId'),
    correlationId,
    q: textParam(params, 'q'),
    from,
    to,
  };
}

export function parseAuditPage(params) {
  const raw = String(params.get('limit') ?? '').trim();
  let limit = AUDIT_PAGE_DEFAULT;
  if (raw) {
    const requested = Number(raw);
    if (!Number.isInteger(requested)) throw new AuditQueryError('limit must be an integer');
    limit = Math.min(Math.max(requested, 1), AUDIT_PAGE_MAX);
  }
  return { limit, before: decodeAuditCursor(params.get('before')) };
}

// Export needs an explicit window, so a file always states the period it covers.
export function parseAuditExport(params) {
  const filters = parseAuditFilters(params);
  if (!filters.from || !filters.to) throw new AuditQueryError('An export needs both from and to');
  const format = String(params.get('format') ?? 'csv')
    .trim()
    .toLowerCase();
  if (format !== 'csv') throw new AuditQueryError('Only format=csv is supported');
  return filters;
}

// The query string of a set of filters (the screen sends these; defaults are left out).
export function auditFilterParams(filters = {}) {
  const params = new URLSearchParams();
  if (filters.category && filters.category !== 'all') params.set('category', filters.category);
  if (filters.failuresOnly) params.set('failures', 'true');
  for (const name of ['actor', 'resourceType', 'resourceId', 'correlationId', 'q', 'from', 'to']) {
    const value = String(filters[name] ?? '').trim();
    if (value) params.set(name, value);
  }
  return params;
}

// ── Memory store: the same semantics as the SQL below ─────────────────────────
function resourceOf(event) {
  return [event.resourceType, event.resourceId].filter(Boolean).join(':');
}

export function matchesAuditFilters(event, filters, { ignoreCategory = false } = {}) {
  if (!ignoreCategory && filters.category && filters.category !== 'all') {
    if (auditCategoryOf(event.eventType).key !== filters.category) return false;
  }
  if (filters.failuresOnly && event.outcome === 'success') return false;
  if (filters.actor && event.actorId !== filters.actor) return false;
  if (filters.resourceType && event.resourceType !== filters.resourceType) return false;
  if (filters.resourceId && event.resourceId !== filters.resourceId) return false;
  if (
    filters.correlationId &&
    String(event.correlationId || '').toLowerCase() !== filters.correlationId
  )
    return false;
  const at = Date.parse(event.occurredAt);
  if (filters.from && !(at >= Date.parse(filters.from))) return false;
  if (filters.to && !(at < Date.parse(filters.to))) return false;
  if (filters.q) {
    const needle = filters.q.toLowerCase();
    const haystack = [
      event.summary,
      event.eventType,
      event.actorId,
      resourceOf(event),
      event.correlationId,
    ];
    if (
      !haystack.some((value) =>
        String(value || '')
          .toLowerCase()
          .includes(needle),
      )
    )
      return false;
  }
  return true;
}

// Newest first; ties broken by id, as in PostgreSQL (uuid order = lower-case hex order).
export function compareAuditEvents(left, right) {
  const byTime = BigInt(micros(right.occurredAt)) - BigInt(micros(left.occurredAt));
  if (byTime !== 0n) return byTime > 0n ? 1 : -1;
  const a = String(left.id).toLowerCase();
  const b = String(right.id).toLowerCase();
  return a < b ? 1 : a > b ? -1 : 0;
}

export function isBeforeCursor(event, cursor) {
  if (!cursor) return true;
  const at = BigInt(micros(event.occurredAt));
  const boundary = BigInt(cursor.occurredMicros);
  return at < boundary || (at === boundary && String(event.id).toLowerCase() < cursor.id);
}

// ── PostgreSQL ─────────────────────────────────────────────────────────────────
function likePattern(text) {
  return `%${text.replace(/[\\%_]/g, (character) => `\\${character}`)}%`;
}

// SQL conditions (joined with AND) for the filters; values are appended to `params`.
export function auditSqlConditions(filters, params, { ignoreCategory = false } = {}) {
  const conditions = [];
  const add = (value) => {
    params.push(value);
    return `$${params.length}`;
  };
  if (!ignoreCategory && filters.category && filters.category !== 'all') {
    if (filters.category === AUDIT_OTHER_CATEGORY.key) {
      const prefixes = PREFIXED.map((category) => `${category.prefix}%`);
      conditions.push(`NOT (event_type LIKE ANY(${add(prefixes)}::text[]))`);
    } else {
      const { prefix } = AUDIT_CATEGORIES.find((category) => category.key === filters.category);
      conditions.push(`event_type LIKE ${add(`${prefix}%`)}`);
    }
  }
  if (filters.failuresOnly) conditions.push(`outcome <> 'success'`);
  if (filters.actor) conditions.push(`actor_id = ${add(filters.actor)}`);
  if (filters.resourceType) conditions.push(`resource_type = ${add(filters.resourceType)}`);
  if (filters.resourceId) conditions.push(`resource_id = ${add(filters.resourceId)}`);
  if (filters.correlationId)
    conditions.push(`correlation_id = ${add(filters.correlationId)}::uuid`);
  if (filters.from) conditions.push(`occurred_at >= ${add(filters.from)}::timestamptz`);
  if (filters.to) conditions.push(`occurred_at < ${add(filters.to)}::timestamptz`);
  if (filters.q) {
    const pattern = add(likePattern(filters.q));
    conditions.push(
      `(summary ILIKE ${pattern} ESCAPE '\\' OR event_type ILIKE ${pattern} ESCAPE '\\'` +
        ` OR actor_id ILIKE ${pattern} ESCAPE '\\'` +
        ` OR (resource_type || COALESCE(':' || resource_id, '')) ILIKE ${pattern} ESCAPE '\\'` +
        ` OR correlation_id::text ILIKE ${pattern} ESCAPE '\\')`,
    );
  }
  return conditions;
}

export function auditSqlCursorCondition(cursor, params) {
  if (!cursor) return null;
  params.push(cursor.occurredMicros, cursor.id);
  const at = `(timestamptz 'epoch' + $${params.length - 1}::bigint * interval '1 microsecond')`;
  return `(occurred_at, id) < (${at}, $${params.length}::uuid)`;
}

// ── CSV ────────────────────────────────────────────────────────────────────────
export const AUDIT_CSV_COLUMNS = Object.freeze([
  'Time (UTC)',
  'Event ID',
  'Event type',
  'Category',
  'Summary',
  'Actor',
  'Resource',
  'Outcome',
  'Severity',
  'Correlation ID',
  'Team',
  'Metadata (JSON)',
]);

// RFC 4180 quoting, and no cell a spreadsheet would run as a formula (CSV injection).
export function csvCell(value) {
  let text = value == null ? '' : String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

export function auditCsvLine(cells) {
  return `${cells.map(csvCell).join(',')}\r\n`;
}

export function auditCsvRow(event) {
  return auditCsvLine([
    event.occurredAt,
    event.id,
    event.eventType,
    auditCategoryOf(event.eventType).label,
    event.summary,
    event.actorId,
    resourceOf(event),
    event.outcome,
    event.severity,
    event.correlationId,
    event.tenantId || '',
    JSON.stringify(event.metadata ?? {}),
  ]);
}

export function auditExportFilename(filters) {
  const day = (iso) => String(iso).slice(0, 10).replaceAll('-', '');
  return `ssi-audit-${day(filters.from)}-${day(filters.to)}.csv`;
}
