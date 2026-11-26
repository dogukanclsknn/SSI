// SSI — Remediation rapor dokümanı (Faz 5, Adım 1: Raporlama)
//
// Bu modül iki ayrı sorumluluğu (SRP) bilinçli olarak ayırır:
//   1) buildRemediationReportDocumentModel(job): bir remediation job'ından
//      sunum-bağımsız, düz bir "rapor modeli" üretir (before/after, kapatılan
//      CVE listesi, digest'ler, publish durumu). Hiç HTML üretmez.
//   2) renderRemediationReportDocumentHtml(model): bu modeli kendi kendine
//      yeten, dış bağımlılığı olmayan, yazdırmaya/PDF'e uygun bir HTML
//      dokümanına dönüştürür.
//
// Ayrım sayesinde ileride aynı modelden farklı bir çıktı (ör. server-side PDF
// üretimi) mevcut render kodunu değiştirmeden eklenebilir (Open/Closed).
// Modül saf ve yan etkisizdir; ağ, dosya veya store erişimi yoktur.

import { describeDimension } from './imageComparison.js';

const SEVERITY_KEYS = ['critical', 'high', 'medium', 'low', 'unknown'];

const SEVERITY_LABELS = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  unknown: 'Unknown',
};

function asText(value, fallback = '') {
  return value == null ? fallback : String(value);
}

function asNonNegativeInteger(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : 0;
}

function normalizeSeveritySummary(value) {
  const source = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  return SEVERITY_KEYS.reduce((summary, key) => {
    summary[key] = asNonNegativeInteger(source[key]);
    return summary;
  }, {});
}

function severityTotal(summary) {
  return SEVERITY_KEYS.reduce((total, key) => total + (summary[key] || 0), 0);
}

// Rapor, kullanıcı/registry kaynaklı metinler (imaj adı, CVE, paket, sürüm,
// digest, gerekçe) içerir. HTML'e gömülen HER değer bu fonksiyondan geçmelidir;
// aksi hâlde üretilen doküman HTML enjeksiyonuna açık olur.
export function escapeHtml(value) {
  return asText(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// İndirilecek dosya adı için güvenli bir taban üretir (Content-Disposition ve
// dosya sistemi için). Yalnızca harf, rakam, nokta, tire ve alt çizgi bırakır.
export function remediationReportDocumentFilename(jobId) {
  const safe = asText(jobId)
    .replace(/[^A-Za-z0-9_-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '');
  return safe ? `remediation-report-${safe}` : 'remediation-report';
}

function formatTimestamp(value) {
  const text = asText(value).trim();
  if (!text) return '';
  const parsed = new Date(text);
  if (Number.isNaN(parsed.getTime())) return text;
  return parsed.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC').replace(/Z$/, ' UTC');
}

function mapFinding(finding = {}) {
  return {
    cve: asText(finding.cve, 'UNKNOWN'),
    package: asText(finding.package, '-'),
    from: asText(finding.from, '-'),
    to: asText(finding.to, '-'),
    severity: asText(finding.severity, 'Unknown'),
    cvss: Number(finding.cvss) || 0,
    reason: asText(finding.reason, ''),
  };
}

function normalizeFullImageComparison(comparison) {
  if (!comparison || typeof comparison !== 'object') return null;
  if (comparison.available === false) {
    return { available: false, reason: asText(comparison.reason, 'Full-image scan not available.') };
  }
  const source = comparison.source || {};
  const output = comparison.output || {};
  return {
    available: true,
    sourceFindings: asNonNegativeInteger(source.findings),
    outputFindings: asNonNegativeInteger(output.findings),
    remainingOutsideCanonicalOsScope: asNonNegativeInteger(comparison.remainingOutsideCanonicalOsScope),
  };
}

function comparisonSection(comparison) {
  if (!comparison || !Array.isArray(comparison.dimensions)) return null;
  const packages = comparison.dimensions.find((item) => item.id === 'packages' && item.status === 'available');
  return {
    contractVersion: asText(comparison.contractVersion),
    attention: (comparison.attention || []).map((point) => ({ level: asText(point.level), message: asText(point.message) })),
    dimensions: comparison.dimensions.map((item) => ({ title: asText(item.title), status: asText(item.status), text: describeDimension(item) })),
    packageChanges: packages ? packages.rows.filter((row) => row.changed) : [],
  };
}

// Bir remediation job'ından sunum-bağımsız rapor modeli üretir.
// verified execution job'ı için before/after ve kapatılan CVE listesi dolar;
// dry-run (planned) job'ı için "after" yoktur ve rapor plan aşamasını yansıtır.
export function buildRemediationReportDocumentModel(job, options = {}) {
  if (!job || typeof job !== 'object' || Array.isArray(job)) {
    throw new TypeError('A remediation job object is required to build the report document.');
  }

  const before = normalizeSeveritySummary(job.before);
  const hasAfter = job.after != null;
  const after = hasAfter ? normalizeSeveritySummary(job.after) : null;
  const beforeTotal = severityTotal(before);
  const afterTotal = after ? severityTotal(after) : null;
  const isVerified = String(job.status || '').toLowerCase() === 'verified';

  const closed = (Array.isArray(job.fixed) ? job.fixed : []).map(mapFinding);
  const remaining = (Array.isArray(job.remaining) ? job.remaining : []).map(mapFinding);

  const severityRows = SEVERITY_KEYS.map((key) => ({
    key,
    label: SEVERITY_LABELS[key],
    before: before[key],
    after: after ? after[key] : null,
    delta: after ? before[key] - after[key] : null,
  }));

  // The evidence-time gate on the job is immutable; callers pass the CURRENT gate
  // (derived from publish requests) so the report never shows a stale status.
  const gateSource = options.publishGate || job.publishGate;
  const publishGate = gateSource && typeof gateSource === 'object' ? gateSource : {};

  return {
    generatedAt: asText(options.generatedAt) || new Date().toISOString(),
    job: {
      id: asText(job.id, '-'),
      parentJobId: asText(job.parentJobId, ''),
      mode: asText(job.mode, ''),
      status: asText(job.status, 'Unknown'),
      isVerified,
    },
    image: {
      reference: asText(job.image, '-'),
      os: asText(job.os, ''),
      scanner: asText(job.scanner, 'Trivy'),
      sourceDigest: asText(job.sourceDigest, ''),
      outputDigest: asText(job.patchedImageDigest, ''),
      outputTag: asText(job.patchedImageTag) || asText(job.proposedPatchedTag, ''),
    },
    engine: {
      name: asText(job.engine, 'Copacetic'),
      version: asText(job.engineVersion, ''),
    },
    scope: asText(job.scope, 'os-packages-only'),
    createdAt: asText(job.createdAt, ''),
    verifiedAt: asText(job.verifiedAt, ''),
    severity: {
      rows: severityRows,
      beforeTotal,
      afterTotal,
      closedTotal: after ? Math.max(beforeTotal - afterTotal, 0) : 0,
    },
    closed,
    remaining,
    fullImage: normalizeFullImageComparison(job.fullImageComparison),
    // What changed between the source and the patched image (ssi.image-comparison/v1), when
    // the caller built one: the points to review, one line per dimension, and the package
    // changes, so the document answers "did the fix change anything important?".
    changes: comparisonSection(options.comparison),
    publish: {
      status: asText(publishGate.status, 'Not evaluated'),
      allowed: publishGate.allowed === true,
      reason: asText(publishGate.reason, ''),
    },
    canonical: {
      contentDigest: asText(job.canonicalReport?.contentDigest, ''),
      findingCount: asNonNegativeInteger(job.canonicalReport?.findingCount),
    },
  };
}

function severityBadgeStyle(severityKey) {
  const palette = {
    critical: '#b3261e',
    high: '#c15400',
    medium: '#8a6d00',
    low: '#3a6a3a',
    unknown: '#5a6472',
  };
  return palette[severityKey] || palette.unknown;
}

function renderSeverityRows(rows) {
  return rows
    .map((row) => {
      const afterCell = row.after == null ? '—' : String(row.after);
      // "Kapatılan" kolonu kaç bulgunun kapatıldığını (before - after) pozitif
      // olarak gösterir; toplam satırıyla tutarlı olması için işaret çevrilmez.
      const deltaCell = row.delta == null ? '—' : String(row.delta);
      const deltaClass = row.delta && row.delta > 0 ? 'delta-good' : 'delta-flat';
      return `<tr>
        <td><span class="sev-dot" style="background:${severityBadgeStyle(row.key)}"></span>${escapeHtml(row.label)}</td>
        <td class="num">${row.before}</td>
        <td class="num">${afterCell}</td>
        <td class="num ${deltaClass}">${deltaCell}</td>
      </tr>`;
    })
    .join('\n');
}

function renderFindingRows(findings, { withReason = false } = {}) {
  if (findings.length === 0) {
    const span = withReason ? 5 : 5;
    return `<tr><td class="empty" colspan="${span}">None.</td></tr>`;
  }
  return findings
    .map((finding) => {
      const lastCell = withReason
        ? `<td>${escapeHtml(finding.reason || '-')}</td>`
        : `<td class="num">${finding.cvss ? finding.cvss.toFixed(1) : '-'}</td>`;
      return `<tr>
        <td class="mono">${escapeHtml(finding.cve)}</td>
        <td>${escapeHtml(finding.package)}</td>
        <td class="mono">${escapeHtml(finding.from)} → ${escapeHtml(finding.to)}</td>
        <td><span class="sev-dot" style="background:${severityBadgeStyle(
          finding.severity.toLowerCase(),
        )}"></span>${escapeHtml(finding.severity)}</td>
        ${lastCell}
      </tr>`;
    })
    .join('\n');
}

function renderMetaItem(label, value) {
  if (!value) return '';
  return `<div class="meta-item"><span class="meta-label">${escapeHtml(label)}</span><span class="meta-value">${escapeHtml(
    value,
  )}</span></div>`;
}

// Modeli, dış varlık (font, script, resim) çağırmayan, tek dosyalık,
// yazdırmaya/PDF'e uygun bir HTML dokümanına dönüştürür. Tarayıcıdan
// "PDF olarak kaydet" ile temiz bir A4 rapor çıkar.
export function renderRemediationReportDocumentHtml(model) {
  const statusClass = model.job.isVerified ? 'status-verified' : 'status-planned';
  const headline = model.job.isVerified
    ? `${model.severity.closedTotal} vulnerabilities closed`
    : 'Planned — not yet verified';

  const fullImageBlock = model.fullImage
    ? model.fullImage.available
      ? `<div class="panel">
          <h2>Full-image comparison</h2>
          <p>Source image scan: <strong>${model.fullImage.sourceFindings}</strong> findings → patched image: <strong>${model.fullImage.outputFindings}</strong> findings. <strong>${model.fullImage.remainingOutsideCanonicalOsScope}</strong> findings outside the canonical OS-package scope (application dependencies) are not remediated in this release.</p>
        </div>`
      : `<div class="panel"><h2>Full-image comparison</h2><p class="muted">${escapeHtml(
          model.fullImage.reason,
        )}</p></div>`
    : '';

  const changesBlock = model.changes
    ? `<div class="panel">
    <h2>What changed (source → patched)</h2>
    ${
      model.changes.attention.length
        ? `<ul class="attention">${model.changes.attention
            .map((point) => `<li class="${escapeHtml(point.level)}">${escapeHtml(point.message)}</li>`)
            .join('')}</ul>`
        : '<p class="muted">Nothing needs special attention in the available evidence.</p>'
    }
    <table>
      <thead><tr><th>Dimension</th><th>Result</th></tr></thead>
      <tbody>${model.changes.dimensions
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.title)}</td><td${item.status === 'available' ? '' : ' class="muted"'}>${escapeHtml(item.text)}</td></tr>`,
        )
        .join('')}</tbody>
    </table>
    ${
      model.changes.packageChanges.length
        ? `<h3>OS package changes (${model.changes.packageChanges.length})</h3>
    <table>
      <thead><tr><th>Change</th><th>Package</th><th>Source</th><th>Patched</th><th>Plan</th></tr></thead>
      <tbody>${model.changes.packageChanges
        .map(
          (row) =>
            `<tr><td>${escapeHtml(row.change)}</td><td>${escapeHtml(row.name)}</td><td class="mono">${escapeHtml(row.source || '-')}</td><td class="mono">${escapeHtml(
              row.patched || '-',
            )}</td><td>${escapeHtml(row.planned)}</td></tr>`,
        )
        .join('')}</tbody>
    </table>`
        : ''
    }
  </div>`
    : '';

  const publishReason = model.publish.reason
    ? `<p class="muted">${escapeHtml(model.publish.reason)}</p>`
    : '';

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Remediation Report · ${escapeHtml(model.job.id)}</title>
<style>
  :root {
    --navy: #0b2f5e;
    --navy-soft: #12467f;
    --ink: #1a2230;
    --muted: #5a6472;
    --line: #d9dee6;
    --bg-soft: #f4f6fa;
    --good: #1f7a4d;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
    color: var(--ink);
    background: #fff;
    font-size: 13px;
    line-height: 1.5;
  }
  .page { max-width: 900px; margin: 0 auto; padding: 32px; }
  header.report-head {
    border-bottom: 3px solid var(--navy);
    padding-bottom: 16px;
    margin-bottom: 20px;
  }
  .brand { color: var(--navy); font-weight: 700; letter-spacing: 0.08em; font-size: 12px; text-transform: uppercase; }
  h1 { margin: 6px 0 2px; font-size: 22px; color: var(--navy); }
  .subtitle { color: var(--muted); margin: 0; }
  .status-pill {
    display: inline-block; margin-top: 12px; padding: 5px 12px; border-radius: 999px;
    font-weight: 600; font-size: 12px;
  }
  .status-verified { background: #e5f2ea; color: var(--good); border: 1px solid #b7dcc5; }
  .status-planned { background: #fff4e0; color: #9a6a00; border: 1px solid #f0d9a8; }
  .headline {
    margin: 18px 0; padding: 18px 20px; background: var(--navy); color: #fff; border-radius: 10px;
    display: flex; justify-content: space-between; align-items: baseline; gap: 16px;
  }
  .headline .big { font-size: 26px; font-weight: 700; }
  .headline .small { font-size: 12px; opacity: 0.85; }
  .meta-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 8px 24px; margin: 0 0 20px; }
  .meta-item { display: flex; flex-direction: column; border-bottom: 1px solid var(--line); padding: 6px 0; }
  .meta-label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }
  .meta-value { font-family: "Consolas", "SFMono-Regular", monospace; font-size: 12px; word-break: break-all; }
  .panel { margin: 0 0 22px; }
  h2 { font-size: 15px; color: var(--navy); border-left: 4px solid var(--navy); padding-left: 8px; margin: 0 0 10px; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th, td { text-align: left; padding: 7px 9px; border-bottom: 1px solid var(--line); vertical-align: top; }
  thead th { background: var(--bg-soft); color: var(--navy); font-weight: 600; border-bottom: 2px solid var(--line); }
  td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
  td.mono { font-family: "Consolas", "SFMono-Regular", monospace; }
  td.empty { color: var(--muted); font-style: italic; }
  .delta-good { color: var(--good); font-weight: 700; }
  .delta-flat { color: var(--muted); }
  .sev-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; vertical-align: middle; }
  .muted { color: var(--muted); }
  h3 { font-size: 13px; color: var(--navy); margin: 14px 0 8px; }
  ul.attention { margin: 0 0 12px; padding: 0; list-style: none; }
  ul.attention li { margin: 0 0 6px; padding: 7px 10px; border-radius: 6px; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  ul.attention li.high { background: #fdecea; color: #8a1f15; }
  ul.attention li.warning { background: #fff6e5; color: #7a4b00; }
  ul.attention li.info { background: #eef4ff; color: #1d3f8a; }
  footer.report-foot {
    margin-top: 28px; padding-top: 14px; border-top: 1px solid var(--line);
    font-size: 11px; color: var(--muted); display: flex; justify-content: space-between; gap: 16px;
  }
  @page { size: A4; margin: 16mm; }
  @media print {
    .page { max-width: none; padding: 0; }
    .panel, table { page-break-inside: avoid; }
    .headline { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    thead th, .status-pill, .sev-dot, .headline { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  }
</style>
</head>
<body>
<div class="page">
  <header class="report-head">
    <div class="brand">SSI · Secure Image Factory</div>
    <h1>Remediation Report</h1>
    <p class="subtitle">${escapeHtml(model.image.reference)}</p>
    <span class="status-pill ${statusClass}">${escapeHtml(model.job.status)}</span>
  </header>

  <div class="headline">
    <div><div class="big">${escapeHtml(headline)}</div>
      <div class="small">Canonical OS-package scope: ${model.severity.beforeTotal} → ${
        model.severity.afterTotal == null ? '—' : model.severity.afterTotal
      } findings</div>
    </div>
    <div class="small">Generated: ${escapeHtml(formatTimestamp(model.generatedAt))}</div>
  </div>

  <div class="meta-grid">
    ${renderMetaItem('Job', model.job.id)}
    ${renderMetaItem('Source plan', model.job.parentJobId)}
    ${renderMetaItem('Engine', [model.engine.name, model.engine.version].filter(Boolean).join(' '))}
    ${renderMetaItem('Scanner', model.image.scanner)}
    ${renderMetaItem('Operating system', model.image.os)}
    ${renderMetaItem('Verified', formatTimestamp(model.verifiedAt) || formatTimestamp(model.createdAt))}
    ${renderMetaItem('Source digest', model.image.sourceDigest)}
    ${renderMetaItem('Output digest', model.image.outputDigest)}
  </div>

  ${changesBlock}

  <div class="panel">
    <h2>Before / after by severity</h2>
    <table>
      <thead><tr><th>Severity</th><th class="num">Before</th><th class="num">After</th><th class="num">Closed</th></tr></thead>
      <tbody>
        ${renderSeverityRows(model.severity.rows)}
        <tr>
          <td><strong>Total</strong></td>
          <td class="num"><strong>${model.severity.beforeTotal}</strong></td>
          <td class="num"><strong>${model.severity.afterTotal == null ? '—' : model.severity.afterTotal}</strong></td>
          <td class="num delta-good"><strong>${model.severity.afterTotal == null ? '—' : model.severity.closedTotal}</strong></td>
        </tr>
      </tbody>
    </table>
  </div>

  <div class="panel">
    <h2>Closed vulnerabilities (${model.closed.length})</h2>
    <table>
      <thead><tr><th>CVE</th><th>Package</th><th>Version</th><th>Severity</th><th class="num">CVSS</th></tr></thead>
      <tbody>${renderFindingRows(model.closed)}</tbody>
    </table>
  </div>

  ${
    model.remaining.length > 0
      ? `<div class="panel">
    <h2>Remaining vulnerabilities (${model.remaining.length})</h2>
    <table>
      <thead><tr><th>CVE</th><th>Package</th><th>Version</th><th>Severity</th><th>Reason</th></tr></thead>
      <tbody>${renderFindingRows(model.remaining, { withReason: true })}</tbody>
    </table>
  </div>`
      : ''
  }

  ${fullImageBlock}

  <div class="panel">
    <h2>Publish status</h2>
    <p>Policy gate: <strong>${escapeHtml(model.publish.status)}</strong>${
      model.publish.allowed ? '' : ' — not eligible for central publishing'
    }.</p>
    ${publishReason}
  </div>

  <footer class="report-foot">
    <span>SSI Remediation Report · ${escapeHtml(model.job.id)}</span>
    <span>Internal use only · ${escapeHtml(formatTimestamp(model.generatedAt))}</span>
  </footer>
</div>
</body>
</html>`;
}
