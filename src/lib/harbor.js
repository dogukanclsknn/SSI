export const HARBOR_VULNERABILITY_REPORT_MIME =
  'application/vnd.security.vulnerability.report; version=1.1';

// DİKKAT: Harbor'un repository path segmenti ÇİFT URL-encode bekler.
// Depo adı iç içe olduğunda (ör. "approved/ssi-remediation-test") tek encode
// Harbor tarafında bir kez çözülür, slash geri gelir ve API 404 NOT_FOUND döner.
// Çift encode ("approved%252Fssi-remediation-test") çözümden sonra doğru tek
// segmenti bırakır. Düz adlarda tek ve çift encode aynı baytları üretir, çünkü
// encodeURIComponent rezerve olmayan karakterlere dokunmaz; kural bu yüzden her
// iki durumda da güvenlidir. Tek encode'a sadeleştirmeyin.
export function encodeHarborRepositoryName(name) {
  return encodeURIComponent(encodeURIComponent(String(name ?? '')));
}

function firstObject(values) {
  return values.find((value) => value && typeof value === 'object' && !Array.isArray(value));
}

function asText(value, fallback = '') {
  if (value == null) {
    return fallback;
  }

  return String(value);
}

function firstText(values, fallback = '') {
  const value = values.find((candidate) => candidate != null && String(candidate).trim());
  return value == null ? fallback : asText(value);
}

function normalizeSeverity(severity = 'Unknown') {
  const normalized = asText(severity).trim().toLowerCase();
  const known = {
    critical: 'Critical',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
    negligible: 'Low',
    unknown: 'Unknown',
    none: 'Unknown',
  };

  return known[normalized] || 'Unknown';
}

function numberFrom(values) {
  for (const value of values) {
    const number = Number(value);
    if (Number.isFinite(number)) {
      return number;
    }
  }

  return 0;
}

function scoreFromVulnerability(vulnerability) {
  const preferred = vulnerability.preferred_cvss || vulnerability.preferredCvss || {};
  const cvss = vulnerability.cvss || vulnerability.CVSS || {};
  const nestedCvss = Object.values(cvss).filter((value) => value && typeof value === 'object');

  return numberFrom([
    preferred.score_v3,
    preferred.scoreV3,
    preferred.V3Score,
    preferred.score,
    cvss.score_v3,
    cvss.scoreV3,
    cvss.V3Score,
    cvss.score,
    ...nestedCvss.flatMap((value) => [value.score_v3, value.scoreV3, value.V3Score, value.score]),
  ]);
}

function vectorFromVulnerability(vulnerability) {
  const preferred = vulnerability.preferred_cvss || vulnerability.preferredCvss || {};
  const cvss = vulnerability.cvss || vulnerability.CVSS || {};
  const nestedCvss = Object.values(cvss).filter((value) => value && typeof value === 'object');

  return firstText([
    preferred.vector,
    preferred.vector_v3,
    preferred.vectorV3,
    preferred.V3Vector,
    cvss.vector,
    cvss.vector_v3,
    cvss.vectorV3,
    cvss.V3Vector,
    ...nestedCvss.flatMap((value) => [value.vector, value.vector_v3, value.vectorV3, value.V3Vector]),
  ]);
}

function formatScannedAt(value) {
  const timestamp = asText(value).trim();

  if (!timestamp) {
    return '';
  }

  return timestamp.replace('T', ' ').replace(/\.\d+(?=Z$)/, '').replace(/Z$/, '').slice(0, 16);
}

function vulnerabilityPayload(report) {
  if (Array.isArray(report)) {
    return { vulnerabilities: report };
  }

  if (!report || typeof report !== 'object') {
    return {};
  }

  if (Array.isArray(report.vulnerabilities) || Array.isArray(report.Vulnerabilities)) {
    return report;
  }

  const nested = firstObject([report.report, report.data, ...Object.values(report)]);
  return nested && (Array.isArray(nested.vulnerabilities) || Array.isArray(nested.Vulnerabilities))
    ? nested
    : report;
}

function tagFromArtifact(artifact = {}, reportArtifact = {}) {
  return firstText([
    reportArtifact.tag,
    artifact.tags?.[0]?.name,
    artifact.tag,
  ]);
}

function digestFromArtifact(artifact = {}, reportArtifact = {}) {
  return firstText([
    reportArtifact.digest,
    artifact.digest,
  ]);
}

function imageReference(project, repository, tag, digest) {
  const image = [project, repository].filter(Boolean).join('/');

  if (tag) {
    return `${image}:${tag}`;
  }

  return digest ? `${image}@${digest}` : image || 'unknown:image';
}

export function findHarborScanOverview(artifact = {}) {
  const overview = artifact.scan_overview || artifact.scanOverview || {};
  return firstObject(Object.values(overview)) || null;
}

export function harborScanStatus(overview) {
  return asText(overview?.scan_status || overview?.scanStatus || 'pending').trim().toLowerCase();
}

export function isHarborScanComplete(overview) {
  return ['success', 'completed'].includes(harborScanStatus(overview));
}

export function normalizeHarborVulnerabilityReport({ report, project, repository, artifact = {}, overview = null }) {
  const payload = vulnerabilityPayload(report);
  const reportArtifact = payload.artifact || payload.Artifact || {};
  const tag = tagFromArtifact(artifact, reportArtifact);
  const digest = digestFromArtifact(artifact, reportArtifact);
  const image = imageReference(project, repository, tag, digest);
  const scanner = payload.scanner || payload.Scanner || overview?.scanner || {};
  const vulnerabilities = payload.vulnerabilities || payload.Vulnerabilities || [];
  const payloadClass = firstText([payload.class, payload.Class], 'unknown');
  const payloadType = firstText([payload.type, payload.Type], 'unknown');

  return {
    id: image,
    image,
    digest,
    os: firstText([payload.os, payload.os_name, reportArtifact.os]),
    scanner: firstText([scanner.name, scanner.Name], 'Harbor scanner'),
    scannedAt: formatScannedAt(
      firstText([
        payload.generated_at,
        payload.generatedAt,
        overview?.end_time,
        overview?.endTime,
        artifact.push_time,
        artifact.creation_time,
      ]),
    ),
    artifactType: firstText([reportArtifact.mime_type, artifact.mime_type], 'container_image'),
    schemaVersion: 1,
    findings: vulnerabilities.map((vulnerability) => {
      const fixed = firstText([
        vulnerability.fix_version,
        vulnerability.fixVersion,
        vulnerability.FixedVersion,
      ], '-');
      const links = Array.isArray(vulnerability.links) ? vulnerability.links : [];

      return {
        cve: firstText([vulnerability.id, vulnerability.vulnerability_id, vulnerability.VulnerabilityID], 'UNKNOWN'),
        package: firstText([vulnerability.package, vulnerability.package_name, vulnerability.PkgName], '-'),
        installed: firstText([
          vulnerability.version,
          vulnerability.installed_version,
          vulnerability.installedVersion,
          vulnerability.InstalledVersion,
        ], '-'),
        fixed,
        severity: normalizeSeverity(vulnerability.severity || vulnerability.Severity),
        cvss: scoreFromVulnerability(vulnerability),
        cvssVector: vectorFromVulnerability(vulnerability),
        epss: null,
        status: fixed !== '-' ? 'Fix available' : 'No fix',
        title: firstText([vulnerability.title, vulnerability.id, vulnerability.VulnerabilityID], 'Vulnerability'),
        description: firstText([vulnerability.description, vulnerability.Description]),
        primaryUrl: firstText([
          vulnerability.primary_url,
          vulnerability.primaryUrl,
          vulnerability.PrimaryURL,
          links[0],
        ]),
        target: image,
        class: firstText([vulnerability.class, vulnerability.Class, payloadClass], 'unknown'),
        type: firstText([vulnerability.type, vulnerability.Type, payloadType], 'unknown'),
      };
    }),
  };
}

// ── Harbor envanter yardımcıları (Faz 5, Adım 2a) ───────────────────────────
// Çok-proje + sayfalama desteğinin saf, test edilebilir parçaları. Ağ erişimi
// yoktur; sayfalama, enjekte edilen bir sayfa-getirici üzerinden çalışır.

// HARBOR_PROJECTS (virgülle ayrık) → sırası korunmuş, benzersiz proje listesi.
// Boşsa tek HARBOR_PROJECT değerine düşer (geriye uyumlu).
export function parseHarborProjects(value, fallback = '') {
  const parsed = String(value ?? '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
  const unique = [...new Set(parsed)];
  if (unique.length > 0) {
    return unique;
  }
  const single = String(fallback ?? '').trim();
  return single ? [single] : [];
}

// Harbor repository adı "<project>/<repo>" biçimindedir; ilgili projenin önekini
// kaldırır. Çok-projede doğru repo adı için proje açıkça geçilir (global tek
// projeye bağlı kalınmaz).
export function harborRelativeRepositoryName(project, repository) {
  const name = String((repository && repository.name) || repository || '');
  const prefix = `${project}/`;
  return name.startsWith(prefix) ? name.slice(prefix.length) : name;
}

function severityCountsFromArtifact(artifact) {
  const overview = findHarborScanOverview(artifact);
  const summary = overview?.summary?.summary || {};

  return {
    critical: summary.Critical || summary.critical || 0,
    high: summary.High || summary.high || 0,
    medium: summary.Medium || summary.medium || 0,
    low: summary.Low || summary.low || 0,
  };
}

function maxCvssFromCounts({ critical, high, medium, low }) {
  if (critical > 0) return 9.8;
  if (high > 0) return 7.5;
  if (medium > 0) return 5.3;
  if (low > 0) return 3.1;
  return 0;
}

function statusFromCounts({ critical, high }) {
  if (critical > 0) return 'Blocked';
  if (high > 0) return 'Review';
  return 'Approved';
}

function runtimeFromRepository(repository) {
  const normalized = String(repository).toLowerCase();

  if (normalized.includes('node')) return 'Node.js';
  if (normalized.includes('java')) return 'Java';
  if (normalized.includes('python')) return 'Python';
  if (normalized.includes('dotnet') || normalized.includes('aspnet')) return '.NET';
  if (normalized.includes('nginx')) return 'nginx';
  if (normalized.includes('alpine')) return 'Alpine';
  return 'Container';
}

// Harbor lists Cosign accessories (sha256-<digest>.sig/.att/.sbom) and untagged
// manifests (the tag falls back to the 12-char digest prefix in mapHarborArtifact) as
// separate artifacts. They are not deployable images: the inventory hides them by
// default and production coverage never counts them.
const TECHNICAL_ARTIFACT_TAG = /^sha256-[0-9a-f]{64}\.(sig|att|sbom)$/i;

// A Cosign accessory stored as its own Harbor artifact: every tag is sha256-<digest>.sig/.att/.sbom.
// It holds signatures, attestations or an SBOM, not an operating system, so Harbor cannot scan
// it and scan loading skips it. Untagged artifacts are kept on purpose: an image whose tag was
// moved can still be the source of a remediation and must keep its scan report.
export function isCosignAccessoryArtifact(artifact) {
  const tags = Array.isArray(artifact?.tags) ? artifact.tags.map((tag) => String(tag?.name || '')) : [];
  return tags.length > 0 && tags.every((tag) => TECHNICAL_ARTIFACT_TAG.test(tag));
}

export function isTechnicalArtifact(image) {
  const version = String(image?.version || '');
  if (version === 'untagged' || TECHNICAL_ARTIFACT_TAG.test(version)) return true;
  return /^[0-9a-f]{12}$/i.test(version) && String(image?.digest || '').startsWith(`sha256:${version}`);
}

// Bir Harbor artifact'ini envanter (Image) modeline çevirir. Proje-farkında:
// `id` projeyi de içerir (projeler arası çakışmayı önler) ve `project` alanı
// imajın hangi Harbor projesinden geldiğini taşır (kaynak takibi).
export function mapHarborArtifact({ project, repository, artifact = {} }) {
  const repo = harborRelativeRepositoryName(project, repository);
  const tag = artifact.tags?.[0]?.name || artifact.digest?.slice(7, 19) || 'untagged';
  const overview = findHarborScanOverview(artifact);
  const counts = severityCountsFromArtifact(artifact);
  const digest = artifact.digest || `sha256:${artifact.id || repo}`;

  return {
    id: `harbor-${project}-${repo}-${tag}`.replace(/[^a-zA-Z0-9_-]+/g, '-').toLowerCase(),
    name: `${project}/${repo}`,
    version: tag,
    type: 'Runtime',
    runtime: runtimeFromRepository(repo),
    status: statusFromCounts(counts),
    digest: digest.length > 19 ? `${digest.slice(0, 19)}` : digest,
    // Full immutable digest and project-relative repository, used to match verified
    // supply-chain evidence and to scope production (approved/) coverage.
    fullDigest: String(artifact.digest || '').toLowerCase(),
    repository: repo,
    critical: counts.critical,
    high: counts.high,
    medium: counts.medium,
    low: counts.low,
    maxCvss: maxCvssFromCounts(counts),
    size: artifact.size ? `${Math.max(1, Math.round(artifact.size / 1024 / 1024))} MB` : '-',
    sbom: false,
    signature: false,
    provenance: false,
    baseOs: '-',
    owner: 'Harbor',
    source: 'Harbor',
    project,
    firstOnboarded: (artifact.push_time || artifact.creation_time || '').slice(0, 10) || '-',
    lastScanned:
      overview?.end_time?.replace('T', ' ').slice(0, 16) ||
      artifact.push_time?.replace('T', ' ').slice(0, 16) ||
      '-',
    rebuiltAt: artifact.push_time?.replace('T', ' ').slice(0, 16) || '-',
    consumers: 0,
    tags: ['harbor', project, repo, tag],
  };
}

// Harbor liste endpoint'lerini sayfa sayfa toplar. `fetchPage(page)` bir sayfa
// dizisi döndürür; page_size'dan kısa (veya boş) sayfa gelince durur. maxPages
// kaçak döngüye karşı güvenlik sınırıdır. Ağ/HTTP detayından bağımsızdır.
export async function collectAllPages(fetchPage, { pageSize = 100, maxPages = 50 } = {}) {
  const all = [];

  for (let page = 1; page <= maxPages; page += 1) {
    const items = await fetchPage(page);
    const list = Array.isArray(items) ? items : [];
    all.push(...list);
    if (list.length < pageSize) {
      break;
    }
  }

  return all;
}
