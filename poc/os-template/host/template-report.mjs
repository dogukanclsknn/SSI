#!/usr/bin/env node
// SSI OS template PoC — the before/after report, the fixable gate and the template manifest
// (docs/os-template-poc.md). Runs on the build host after the Packer build.
//
//   node template-report.mjs report --reports-dir DIR [--fail-on-fixable true|false]
//     reads scan-before.json, scan-after.json, packages-before.tsv, packages-after.tsv and
//     kernel-*.txt from DIR, writes scan-report.json and scan-report.md there, and exits 1 when
//     a vulnerability that has a fix is still present after the upgrade (unless disabled).
//
//   node template-report.mjs manifest --artifacts-dir DIR --report FILE --out FILE
//     [--template-name N --template-version V --build-id ID --base-image-url U
//      --base-image-sha256 H --signed true|false --key-id K --tools JSON]
//     writes the template manifest: the draft of the catalog record SSI keeps for a template.
//
// The functions are exported so the rules are unit-tested (src/lib/osTemplateReport.test.js).
import { createHash } from 'node:crypto';
import { createReadStream, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
export const MANIFEST_VERSION = 'ssi.os-template-manifest/v1';
export const REPORT_VERSION = 'ssi.os-template-scan-report/v1';

const text = (value) => (value == null ? '' : String(value).trim());

// Every OS-package vulnerability of a Trivy JSON report, one entry per CVE and package.
export function vulnerabilitiesOf(report) {
  if (!report || typeof report !== 'object' || !Array.isArray(report.Results ?? [])) {
    throw new Error('Not a Trivy JSON report.');
  }
  const seen = new Map();
  for (const result of report.Results ?? []) {
    for (const item of result?.Vulnerabilities ?? []) {
      const id = text(item.VulnerabilityID);
      const pkg = text(item.PkgName);
      if (!id || !pkg) continue;
      const severity = SEVERITIES.includes(text(item.Severity).toUpperCase())
        ? text(item.Severity).toUpperCase()
        : 'UNKNOWN';
      seen.set(`${id}|${pkg}`, {
        id,
        pkg,
        installed: text(item.InstalledVersion),
        fixed: text(item.FixedVersion),
        severity,
      });
    }
  }
  return [...seen.values()].sort(
    (a, b) =>
      SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) ||
      a.id.localeCompare(b.id) ||
      a.pkg.localeCompare(b.pkg),
  );
}

export function countBySeverity(vulnerabilities) {
  const counts = Object.fromEntries(SEVERITIES.map((severity) => [severity.toLowerCase(), 0]));
  for (const item of vulnerabilities) counts[item.severity.toLowerCase()] += 1;
  return {
    total: vulnerabilities.length,
    ...counts,
    fixable: vulnerabilities.filter((item) => item.fixed).length,
  };
}

// Trivy counts a finding per CVE and package: one kernel CVE appears once for every kernel
// package (image, modules, headers, tools …). The same list counted per CVE, each at its highest
// severity, a CVE being fixable when any of its packages has a fix: the number people mean.
export function countUniqueCves(vulnerabilities) {
  const byId = new Map();
  for (const item of vulnerabilities) {
    const seen = byId.get(item.id);
    const rank = SEVERITIES.indexOf(item.severity);
    if (!seen) byId.set(item.id, { rank, fixable: Boolean(item.fixed) });
    else {
      seen.rank = Math.min(seen.rank, rank);
      seen.fixable ||= Boolean(item.fixed);
    }
  }
  const counts = Object.fromEntries(SEVERITIES.map((severity) => [severity.toLowerCase(), 0]));
  let fixable = 0;
  for (const { rank, fixable: hasFix } of byId.values()) {
    counts[SEVERITIES[rank].toLowerCase()] += 1;
    if (hasFix) fixable += 1;
  }
  return { total: byId.size, ...counts, fixable };
}

// The operating system Trivy recognised, e.g. { family: 'ubuntu', name: '24.04' }, or null.
// A scan in which Trivy saw no operating system reports no OS vulnerability at all.
export function osOf(report) {
  const os = report?.Metadata?.OS;
  const family = text(os?.Family).toLowerCase();
  if (!family || family === 'none') return null;
  return { family, name: text(os?.Name) };
}

// "name<TAB>version" lines → Map(name → version).
export function parsePackages(tsv) {
  const packages = new Map();
  for (const line of String(tsv || '').split('\n')) {
    const [name, version] = line.split('\t');
    if (text(name)) packages.set(text(name), text(version));
  }
  return packages;
}

export function comparePackages(before, after) {
  const upgraded = [];
  const added = [];
  const removed = [];
  for (const [name, version] of after) {
    if (!before.has(name)) added.push({ name, version });
    else if (before.get(name) !== version)
      upgraded.push({ name, from: before.get(name), to: version });
  }
  for (const [name, version] of before) if (!after.has(name)) removed.push({ name, version });
  const byName = (a, b) => a.name.localeCompare(b.name);
  return {
    upgraded: upgraded.sort(byName),
    added: added.sort(byName),
    removed: removed.sort(byName),
  };
}

// The comparison and the gate: a template may not ship with a vulnerability that already has a
// fix, the same rule the container publish policy applies.
export function buildScanReport({
  before,
  after,
  packagesBefore = new Map(),
  packagesAfter = new Map(),
  kernelBefore = '',
  kernelAfter = '',
  failOnFixable = true,
  minimized = null,
  os = null,
}) {
  const key = (item) => `${item.id}|${item.pkg}`;
  const ids = (items) => new Set(items.map((item) => item.id));
  const beforeIds = ids(before);
  const afterIds = ids(after);
  const afterKeys = new Set(after.map(key));
  const beforeKeys = new Set(before.map(key));
  const resolved = before.filter((item) => !afterKeys.has(key(item)));
  const introduced = after.filter((item) => !beforeKeys.has(key(item)));
  const remainingFixable = after.filter((item) => item.fixed);
  const remainingUnfixed = after.filter((item) => !item.fixed);
  const blocked = failOnFixable && remainingFixable.length > 0;
  return {
    reportVersion: REPORT_VERSION,
    before: countBySeverity(before),
    after: countBySeverity(after),
    resolved: countBySeverity(resolved),
    introduced: countBySeverity(introduced),
    // The same, per CVE: a CVE is resolved when no package has it any more, and new only when no
    // package had it before (a renamed kernel package carries its old CVEs; they are not new).
    cves: {
      before: countUniqueCves(before),
      after: countUniqueCves(after),
      resolved: countUniqueCves(before.filter((item) => !afterIds.has(item.id))),
      introduced: countUniqueCves(after.filter((item) => !beforeIds.has(item.id))),
    },
    os,
    kernel: { before: text(kernelBefore), after: text(kernelAfter) },
    packages: comparePackages(packagesBefore, packagesAfter),
    remainingFixable,
    remainingUnfixed,
    resolvedItems: resolved,
    introducedItems: introduced,
    // The template profile's removals (guest/minimize.sh), when a profile was applied.
    minimized,
    gate: {
      rule: 'no-fixable-vulnerability-after-patch',
      enforced: failOnFixable,
      passed: !blocked,
      reason: blocked
        ? `${remainingFixable.length} vulnerabilit${remainingFixable.length === 1 ? 'y has' : 'ies have'} a fix but ${remainingFixable.length === 1 ? 'is' : 'are'} still present after the upgrade.`
        : 'No vulnerability with an available fix remains.',
    },
  };
}

const row = (cells) => `| ${cells.join(' | ')} |`;

export function renderMarkdown(report, { templateName = '', templateVersion = '' } = {}) {
  const sevRow = (label, counts) =>
    row([
      label,
      counts.total,
      counts.critical,
      counts.high,
      counts.medium,
      counts.low,
      counts.unknown,
      counts.fixable,
    ]);
  const lines = [
    `# OS template scan report${templateName ? `: ${templateName} ${templateVersion}`.trimEnd() : ''}`,
    '',
    `**Gate:** ${report.gate.passed ? 'PASSED' : 'FAILED'} — ${report.gate.reason}`,
    ...(report.os ? ['', `Scanned as: ${report.os.family} ${report.os.name}`.trimEnd()] : []),
    ...(report.cves
      ? [
          '',
          '### CVEs (each CVE once, at its highest severity)',
          '',
          row(['', 'CVEs', 'Critical', 'High', 'Medium', 'Low', 'Unknown', 'With a fix']),
          row(['---', '---:', '---:', '---:', '---:', '---:', '---:', '---:']),
          sevRow('Before the upgrade', report.cves.before),
          sevRow('After the upgrade', report.cves.after),
          sevRow('Resolved', report.cves.resolved),
          sevRow('New', report.cves.introduced),
          '',
          '### Findings (one per CVE and package)',
        ]
      : []),
    '',
    row(['', 'Total', 'Critical', 'High', 'Medium', 'Low', 'Unknown', 'With a fix']),
    row(['---', '---:', '---:', '---:', '---:', '---:', '---:', '---:']),
    sevRow('Before the upgrade', report.before),
    sevRow('After the upgrade', report.after),
    sevRow('Resolved', report.resolved),
    sevRow('New', report.introduced),
    '',
    `Kernel: ${report.kernel.before || 'unknown'} → ${report.kernel.after || 'unknown'}. Packages upgraded: ${report.packages.upgraded.length}, added: ${report.packages.added.length}, removed: ${report.packages.removed.length}.`,
  ];
  const list = (title, items) => {
    if (items.length === 0) return;
    lines.push(
      '',
      `## ${title} (${items.length})`,
      '',
      row(['CVE', 'Package', 'Installed', 'Fixed in', 'Severity']),
      row(['---', '---', '---', '---', '---']),
    );
    for (const item of items.slice(0, 200))
      lines.push(row([item.id, item.pkg, item.installed, item.fixed || '—', item.severity]));
    if (items.length > 200) lines.push('', `… ${items.length - 200} more in scan-report.json.`);
  };
  if (report.minimized) {
    const { profile, removed, skipped } = report.minimized;
    lines.push(
      '',
      `Template profile ${profile || '(unnamed)'}: ${removed.length} package(s) removed${skipped.length > 0 ? `; listed but not installed: ${skipped.join(', ')}` : ''}.`,
    );
    if (removed.length > 0) {
      lines.push(
        '',
        `## Removed by the template profile (${removed.length})`,
        '',
        row(['Package', 'Version', 'Why']),
        row(['---', '---', '---']),
      );
      for (const item of removed) lines.push(row([item.name, item.version, item.reason]));
    }
  }
  list('Still present with a fix (blocks the template)', report.remainingFixable);
  list('Still present, no fix released yet', report.remainingUnfixed);
  return `${lines.join('\n')}\n`;
}

// SHA-256 of a file, streamed (template disks are gigabytes).
export function sha256File(path) {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    createReadStream(path)
      .on('data', (chunk) => hash.update(chunk))
      .on('error', reject)
      .on('end', () => resolve(hash.digest('hex')));
  });
}

const FORMAT_OF = {
  '.qcow2': { format: 'qcow2', platforms: ['proxmox', 'kvm'] },
  '.ova': { format: 'ova', platforms: ['vmware-vsphere'] },
  '.vhdx': { format: 'vhdx', platforms: ['hyper-v'] },
};

export async function buildManifest({
  artifactsDir,
  report,
  templateName,
  templateVersion,
  buildId,
  baseImageUrl,
  baseImageSha256,
  signed,
  keyId,
  tools = {},
  createdAt = new Date().toISOString(),
}) {
  const artifacts = [];
  for (const name of readdirSync(artifactsDir).sort()) {
    const extension = Object.keys(FORMAT_OF).find((suffix) => name.endsWith(suffix));
    if (!extension) continue;
    const path = join(artifactsDir, name);
    artifacts.push({
      file: name,
      ...FORMAT_OF[extension],
      sizeBytes: statSync(path).size,
      sha256: await sha256File(path),
      signature: signed ? `${name}.sig` : null,
    });
  }
  if (artifacts.length === 0) throw new Error(`No .qcow2, .ova or .vhdx file in ${artifactsDir}.`);
  return {
    manifestVersion: MANIFEST_VERSION,
    template: {
      name: templateName,
      version: templateVersion,
      os: 'ubuntu-24.04',
      architecture: 'amd64',
    },
    build: { id: buildId, createdAt, tools },
    base: { url: baseImageUrl, sha256: baseImageSha256 },
    scan: {
      before: report.before,
      after: report.after,
      resolved: report.resolved,
      cves: report.cves ?? null,
      os: report.os ?? null,
      kernel: report.kernel,
      packagesUpgraded: report.packages.upgraded.length,
      gate: report.gate,
      profile: report.minimized
        ? {
            name: report.minimized.profile,
            removed: report.minimized.removed.map((item) => item.name),
          }
        : null,
    },
    artifacts,
    signing: signed
      ? {
          signed: true,
          tool: tools.cosign ? `cosign ${tools.cosign}` : 'cosign',
          keyId: keyId || null,
          publicKey: 'cosign.pub',
        }
      : { signed: false },
  };
}

// ── CLI ──────────────────────────────────────────────────────────────────────
function options(argv) {
  const parsed = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    if (!name?.startsWith('--') || argv[index + 1] === undefined)
      throw new Error(`Unexpected argument: ${name}`);
    parsed[name.slice(2)] = argv[index + 1];
  }
  return parsed;
}

const flag = (value, fallback) =>
  value === undefined ? fallback : ['true', '1', 'yes'].includes(String(value).toLowerCase());
const readText = (path) => {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return '';
  }
};

// minimize-plan.tsv / minimize-removed.tsv / minimize-skipped.txt of guest/minimize.sh, or null
// when no profile was applied.
export function parseMinimized({ plan = '', removed = '', skipped = '', profile = '' }) {
  if (!plan.trim() && !removed.trim() && !skipped.trim()) return null;
  const reasons = new Map(
    plan
      .split('\n')
      .filter(Boolean)
      .map((line) => {
        const [name, , reason] = line.split('\t');
        return [name, reason || 'requested'];
      }),
  );
  return {
    profile: text(profile),
    removed: removed
      .split('\n')
      .filter(Boolean)
      .map((line) => {
        const [name, version] = line.split('\t');
        return {
          name: text(name),
          version: text(version),
          reason: reasons.get(text(name)) || 'requested',
        };
      }),
    skipped: skipped.split('\n').map(text).filter(Boolean),
  };
}

function readMinimized(dir, profile) {
  return parseMinimized({
    plan: readText(join(dir, 'minimize-plan.tsv')),
    removed: readText(join(dir, 'minimize-removed.tsv')),
    skipped: readText(join(dir, 'minimize-skipped.txt')),
    profile,
  });
}

async function main([command, ...argv]) {
  const opts = options(argv);
  if (command === 'report') {
    const dir = opts['reports-dir'];
    if (!dir) throw new Error('--reports-dir is required.');
    const scanBefore = JSON.parse(readFileSync(join(dir, 'scan-before.json'), 'utf8'));
    const scanAfter = JSON.parse(readFileSync(join(dir, 'scan-after.json'), 'utf8'));
    const report = buildScanReport({
      before: vulnerabilitiesOf(scanBefore),
      after: vulnerabilitiesOf(scanAfter),
      os: osOf(scanAfter) ?? osOf(scanBefore),
      packagesBefore: parsePackages(readText(join(dir, 'packages-before.tsv'))),
      packagesAfter: parsePackages(readText(join(dir, 'packages-after.tsv'))),
      kernelBefore: readText(join(dir, 'kernel-before.txt')),
      kernelAfter: readText(join(dir, 'kernel-after.txt')),
      failOnFixable: flag(opts['fail-on-fixable'], true),
      minimized: readMinimized(dir, opts.profile),
    });
    writeFileSync(join(dir, 'scan-report.json'), `${JSON.stringify(report, null, 2)}\n`);
    writeFileSync(
      join(dir, 'scan-report.md'),
      renderMarkdown(report, {
        templateName: opts['template-name'],
        templateVersion: opts['template-version'],
      }),
    );
    const { before, after } = report;
    console.log(
      `Vulnerabilities: ${before.total} before (${before.critical} critical, ${before.high} high), ${after.total} after (${after.critical} critical, ${after.high} high).`,
    );
    console.log(
      `Unique CVEs: ${report.cves.before.total} before (${report.cves.before.fixable} with a fix), ${report.cves.after.total} after (${report.cves.after.fixable} with a fix).`,
    );
    console.log(`Gate ${report.gate.passed ? 'passed' : 'FAILED'}: ${report.gate.reason}`);
    return report.gate.passed ? 0 : 1;
  }
  if (command === 'manifest') {
    for (const name of ['artifacts-dir', 'report', 'out'])
      if (!opts[name]) throw new Error(`--${name} is required.`);
    const manifest = await buildManifest({
      artifactsDir: opts['artifacts-dir'],
      report: JSON.parse(readFileSync(opts.report, 'utf8')),
      templateName: opts['template-name'] || '',
      templateVersion: opts['template-version'] || '',
      buildId: opts['build-id'] || '',
      baseImageUrl: opts['base-image-url'] || '',
      baseImageSha256: opts['base-image-sha256'] || '',
      signed: flag(opts.signed, false),
      keyId: opts['key-id'] || '',
      tools: opts.tools ? JSON.parse(opts.tools) : {},
    });
    writeFileSync(opts.out, `${JSON.stringify(manifest, null, 2)}\n`);
    console.log(
      `Manifest: ${manifest.artifacts.map((item) => `${item.file} (${item.sha256.slice(0, 12)})`).join(', ')} → ${basename(opts.out)}`,
    );
    return 0;
  }
  throw new Error('usage: template-report.mjs report|manifest [options]');
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (error) => {
      console.error(error.message);
      process.exit(2);
    },
  );
}
