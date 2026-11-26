import { describe, expect, it } from 'vitest';
import {
  buildRemediationReportDocumentModel,
  renderRemediationReportDocumentHtml,
  remediationReportDocumentFilename,
  escapeHtml,
} from './remediationReportDocument.js';

const verifiedJob = {
  id: 'RM-EXEC-0001',
  parentJobId: 'RM-DRY-0001',
  mode: 'execution',
  status: 'Verified',
  image: 'harbor.example.com/team/app:1.2.3',
  os: 'debian 12',
  scanner: 'Trivy',
  engine: 'Copacetic',
  engineVersion: 'v0.14.2',
  sourceDigest: 'sha256:' + 'a'.repeat(64),
  patchedImageDigest: 'sha256:' + 'b'.repeat(64),
  patchedImageTag: 'harbor.example.com/team/app:1.2.3-copa-r1',
  createdAt: '2026-07-21T14:30:00.000Z',
  verifiedAt: '2026-07-21T14:35:00.000Z',
  before: { critical: 19, high: 19, medium: 25, low: 1, unknown: 0 },
  after: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
  fixed: [
    { cve: 'CVE-2024-0001', package: 'openssl', from: '1.1.1', to: '1.1.1w', severity: 'Critical', cvss: 9.8 },
    { cve: 'CVE-2024-0002', package: 'glibc', from: '2.31', to: '2.31-13', severity: 'High', cvss: 7.5 },
  ],
  remaining: [],
  fullImageComparison: {
    available: true,
    source: { findings: 77 },
    output: { findings: 13 },
    remainingOutsideCanonicalOsScope: 13,
  },
  publishGate: { allowed: false, status: 'Blocked', reason: 'Verified PoC output is not approved for central publish.' },
  canonicalReport: { contentDigest: 'sha256:' + 'c'.repeat(64), findingCount: 64 },
};

const plannedJob = {
  id: 'RM-DRY-0002',
  mode: 'dry-run',
  status: 'Planned',
  image: 'harbor.example.com/team/other:source',
  os: 'ubuntu 22.04',
  engine: 'Copacetic',
  engineVersion: 'v0.14.2',
  before: { critical: 1, high: 0, medium: 2, low: 0, unknown: 0 },
  after: null,
  fixed: [],
  remaining: [],
  createdAt: '2026-07-21T15:00:00.000Z',
};

describe('buildRemediationReportDocumentModel', () => {
  it('computes before/after totals, delta and closed CVEs for a verified job', () => {
    const model = buildRemediationReportDocumentModel(verifiedJob, { generatedAt: '2026-09-02T09:00:00.000Z' });

    expect(model.job.isVerified).toBe(true);
    expect(model.severity.beforeTotal).toBe(64);
    expect(model.severity.afterTotal).toBe(0);
    expect(model.severity.closedTotal).toBe(64);
    expect(model.closed).toHaveLength(2);
    expect(model.closed[0]).toMatchObject({ cve: 'CVE-2024-0001', package: 'openssl', from: '1.1.1', to: '1.1.1w' });

    const criticalRow = model.severity.rows.find((row) => row.key === 'critical');
    expect(criticalRow).toMatchObject({ before: 19, after: 0, delta: 19 });
    expect(model.fullImage).toMatchObject({ available: true, sourceFindings: 77, outputFindings: 13 });
    expect(model.publish).toMatchObject({ status: 'Blocked', allowed: false });
  });

  it('handles a planned dry-run job without an after snapshot', () => {
    const model = buildRemediationReportDocumentModel(plannedJob);

    expect(model.job.isVerified).toBe(false);
    expect(model.severity.beforeTotal).toBe(3);
    expect(model.severity.afterTotal).toBeNull();
    expect(model.severity.closedTotal).toBe(0);
    expect(model.closed).toEqual([]);
    const criticalRow = model.severity.rows.find((row) => row.key === 'critical');
    expect(criticalRow.after).toBeNull();
    expect(criticalRow.delta).toBeNull();
  });

  it('normalizes an unavailable full-image comparison', () => {
    const model = buildRemediationReportDocumentModel({
      ...verifiedJob,
      fullImageComparison: { available: false, reason: 'reports missing' },
    });
    expect(model.fullImage).toEqual({ available: false, reason: 'reports missing' });
  });

  it('throws when the job is missing', () => {
    expect(() => buildRemediationReportDocumentModel(null)).toThrow(TypeError);
    expect(() => buildRemediationReportDocumentModel([])).toThrow(TypeError);
  });
});

describe('renderRemediationReportDocumentHtml', () => {
  it('renders a self-contained HTML document with key values', () => {
    const model = buildRemediationReportDocumentModel(verifiedJob, { generatedAt: '2026-09-02T09:00:00.000Z' });
    const html = renderRemediationReportDocumentHtml(model);

    expect(html.startsWith('<!doctype html>')).toBe(true);
    expect(html).toContain('RM-EXEC-0001');
    expect(html).toContain('64 vulnerabilities closed');
    expect(html).toContain('CVE-2024-0001');
    expect(html).toContain('openssl');
    // Dış varlık çağrısı olmamalı (air-gap / CSP dostu).
    expect(html).not.toMatch(/https?:\/\//);
    expect(html).not.toContain('<script');
  });

  it('escapes hostile values to prevent HTML injection in the document', () => {
    const model = buildRemediationReportDocumentModel({
      ...verifiedJob,
      image: '<img src=x onerror=alert(1)>',
      fixed: [{ cve: '<script>alert(2)</script>', package: 'p', from: '1', to: '2', severity: 'High', cvss: 5 }],
    });
    const html = renderRemediationReportDocumentHtml(model);

    expect(html).not.toContain('<img src=x onerror=alert(1)>');
    expect(html).not.toContain('<script>alert(2)</script>');
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(html).toContain('&lt;script&gt;alert(2)&lt;/script&gt;');
  });

  it('shows the planned state instead of a fake closed count', () => {
    const html = renderRemediationReportDocumentHtml(buildRemediationReportDocumentModel(plannedJob));
    expect(html).toContain('Planned — not yet verified');
  });

  it('renders the closed column as positive counts consistent with the total', () => {
    const html = renderRemediationReportDocumentHtml(buildRemediationReportDocumentModel(verifiedJob));
    // critical before 19 -> after 0 => 19 closed, shown positive (no leading minus)
    expect(html).toContain('>19<');
    // A cell, not any '-19': the generation date (e.g. 2026-11-19) is on the page too.
    expect(html).not.toContain('>-19<');
    // total closed matches the sum
    expect(html).toContain('64 vulnerabilities closed');
  });
});

describe('remediationReportDocumentFilename', () => {
  it('produces a safe filename base', () => {
    expect(remediationReportDocumentFilename('RM-EXEC-0001')).toBe('remediation-report-RM-EXEC-0001');
  });

  it('sanitizes unsafe characters and falls back', () => {
    expect(remediationReportDocumentFilename('../../etc/passwd')).toBe('remediation-report-etc-passwd');
    expect(remediationReportDocumentFilename('')).toBe('remediation-report');
    expect(remediationReportDocumentFilename('///')).toBe('remediation-report');
  });
});

describe('escapeHtml', () => {
  it('escapes the five significant characters', () => {
    expect(escapeHtml(`<>&"'`)).toBe('&lt;&gt;&amp;&quot;&#39;');
  });
});

describe('report publish status', () => {
  it('uses the current publish gate passed by the caller instead of the evidence-time gate', () => {
    const job = { id: 'RM-EXEC-0009', status: 'Verified', publishGate: { status: 'Blocked', allowed: false } };
    const model = buildRemediationReportDocumentModel(job, {
      publishGate: { status: 'Published', allowed: true, reason: 'Approved central publish completed (PUB-0001).' },
    });
    expect(model.publish).toEqual({
      status: 'Published',
      allowed: true,
      reason: 'Approved central publish completed (PUB-0001).',
    });
    expect(buildRemediationReportDocumentModel(job).publish.status).toBe('Blocked');
  });
});

describe('what changed (image comparison) in the report document', () => {
  const comparison = {
    contractVersion: 'ssi.image-comparison/v1',
    attention: [{ level: 'high', message: '1 package change(s) were not in the remediation plan. <script>' }],
    dimensions: [
      {
        id: 'packages',
        title: 'OS packages',
        status: 'available',
        summary: { changed: 1, added: 0, removed: 0, unchanged: 69, unplanned: 1 },
        rows: [{ change: 'changed', name: 'openssl', source: '3.3.2-r0', patched: '4.0.0-r0', planned: 'Not in the plan', changed: true }],
      },
      { id: 'layers', title: 'Layers and size', status: 'unavailable', note: 'The candidate test worker does not report image layers yet.', rows: [] },
    ],
  };

  it('lists the points to review, one line per dimension and the package changes', () => {
    const model = buildRemediationReportDocumentModel(verifiedJob, { comparison, generatedAt: '2026-11-10T10:00:00.000Z' });
    expect(model.changes.dimensions).toEqual([
      { title: 'OS packages', status: 'available', text: '1 changed, 0 added, 0 removed, 69 unchanged; 1 not in the plan.' },
      { title: 'Layers and size', status: 'unavailable', text: 'Not available: The candidate test worker does not report image layers yet.' },
    ]);
    const html = renderRemediationReportDocumentHtml(model);
    expect(html).toContain('What changed (source → patched)');
    expect(html).toContain('OS package changes (1)');
    expect(html).toContain('4.0.0-r0');
    expect(html).not.toContain('<script>');
    expect(html).toContain('&lt;script&gt;');
  });

  it('leaves the section out when no comparison was built', () => {
    const model = buildRemediationReportDocumentModel(verifiedJob, {});
    expect(model.changes).toBeNull();
    expect(renderRemediationReportDocumentHtml(model)).not.toContain('What changed');
  });
});
