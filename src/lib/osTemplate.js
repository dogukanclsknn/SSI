// SSI — OS templates: an up-to-date operating system template built from an official source
// image (docs/os-template-poc.md, "Windows" and "Ubuntu"). Pure functions, no I/O.
//
// Two operating systems, each with its own request, worker and evidence rules (a profile):
//   windows       an official ISO serviced offline (azure-pipelines-os-template-windows.yml,
//                 poc/os-template/windows/Build-WindowsTemplate.ps1); no CVE may stay open (MSRC)
//   ubuntu-24.04  the official cloud image upgraded offline (azure-pipelines-os-template-ubuntu.yml,
//                 poc/os-template/linux/build-ubuntu-template.sh); no CVE with a fix may stay
//                 (Trivy, which must have recognised Ubuntu 24.04)
// A request without `os` is a Windows request (the records made before Ubuntu existed).
//
// Life of a build request (OST-…):
//   Requested  created by an operator with the pinned source image; the worker of its OS can be
//              started for it, again after a failed run.
//   Built      the worker delivered its HMAC-signed result (ssi.os-template-build/v1): the
//              template manifest, bound to this request's source image and name, re-checked
//              here against the OS profile's rules.
//   Approved   an approver accepted the built template into the catalog (four eyes unless
//              disabled, as for publishing).
//   Rejected   an approver closed the request, with a reason.
// Running and failed runs are not states of their own: they are the request's pipeline runs.

import {
  artifactLayoutOf,
  downloadsUnavailableReason,
  osTemplateDownloads,
} from './osTemplateDownloads.js';

export const OS_TEMPLATE_BUILD_CONTRACT = 'ssi.os-template-build/v1';
export const OS_TEMPLATE_MANIFEST_VERSION = 'ssi.os-template-manifest/v1';
export const OS_TEMPLATE_STATES = Object.freeze(['Requested', 'Built', 'Approved', 'Rejected']);
export const OS_TEMPLATE_BUILD_ID = /^OST-[0-9]{4,}$/;

const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;
const MAX_ISO_BYTES = 32 * 1024 ** 3;
const MAX_UPDATES = 20;
const sha256Hex = /^[a-f0-9]{64}$/;
const isoFilePattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,120}\.iso$/;
const msuFilePattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,200}\.msu$/;
const templateNamePattern = /^[a-z0-9][a-z0-9-]{1,40}$/;
const productPattern = /^Windows Server [0-9]{4}( \([A-Za-z ]+\))?$/;
const buildVersionPattern = /^[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,6}\.[0-9]{1,6}$/;
const workerBuildIdPattern = /^[A-Za-z0-9._-]{1,64}$/;
const hostPattern = /^[A-Za-z0-9][A-Za-z0-9-]{0,62}$/;
const windowsPathPattern = /^[A-Za-z]:\\[^\0<>"|?*]{1,400}\.iso$/;

export class OsTemplateError extends Error {
  constructor(message, statusCode = 422) {
    super(message);
    this.name = 'OsTemplateError';
    this.statusCode = statusCode;
  }
}

function assertValid(condition, message, statusCode) {
  if (!condition) throw new OsTemplateError(message, statusCode);
}

const text = (value) => (value == null ? '' : String(value).trim());
const isPlainObject = (value) =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

function hasOnlyPrintable(value) {
  for (const character of value) {
    const code = character.codePointAt(0);
    if (code < 32 || code === 127) return false;
  }
  return true;
}

function boundedText(value, label, { max, required = false }) {
  const normalized = text(value);
  assertValid(!required || normalized.length > 0, `${label} is required.`);
  assertValid(normalized.length <= max, `${label} must be at most ${max} characters.`);
  assertValid(hasOnlyPrintable(normalized), `${label} contains control characters.`);
  return normalized;
}

function matching(value, pattern, message) {
  const normalized = text(value);
  assertValid(pattern.test(normalized), message);
  return normalized;
}

function count(value, label) {
  assertValid(
    Number.isSafeInteger(value) && value >= 0,
    `${label} must be a whole number of at least 0.`,
  );
  return value;
}

function isoTimestamp(value, label, now) {
  const normalized = text(value);
  const time = Date.parse(normalized);
  assertValid(normalized && Number.isFinite(time), `${label} must be an ISO-8601 timestamp.`);
  assertValid(time <= now + MAX_FUTURE_SKEW_MS, `${label} is in the future.`);
  return new Date(time).toISOString();
}

// "10.0.26100.33822" compared part by part.
export function compareBuilds(left, right) {
  const a = text(left).split('.').map(Number);
  const b = text(right).split('.').map(Number);
  for (let index = 0; index < 4; index += 1) {
    if ((a[index] || 0) !== (b[index] || 0)) return (a[index] || 0) - (b[index] || 0);
  }
  return 0;
}

// ── Request ─────────────────────────────────────────────────────────────────────

export const OS_TEMPLATE_OS = Object.freeze({ WINDOWS: 'windows', UBUNTU: 'ubuntu-24.04' });

// The operating system of a request (or of its input): Windows unless it says Ubuntu 24.04.
export function osTemplateOsOf(request) {
  return request?.os === OS_TEMPLATE_OS.UBUNTU ? OS_TEMPLATE_OS.UBUNTU : OS_TEMPLATE_OS.WINDOWS;
}

// The operator's input, with the same rules the worker pipeline applies to its parameters.
export function validateBuildRequest(input) {
  assertValid(isPlainObject(input), 'The build request must be a JSON object.', 400);
  const os = text(input.os);
  assertValid(
    ['', OS_TEMPLATE_OS.WINDOWS, OS_TEMPLATE_OS.UBUNTU].includes(os),
    `os must be ${OS_TEMPLATE_OS.WINDOWS} or ${OS_TEMPLATE_OS.UBUNTU}.`,
  );
  return os === OS_TEMPLATE_OS.UBUNTU
    ? validateUbuntuRequest(input)
    : validateWindowsRequest(input);
}

// Windows: the shape every request had before Ubuntu (no `os` field).
function validateWindowsRequest(input) {
  const imageIndex = Number(input.imageIndex);
  assertValid(
    Number.isInteger(imageIndex) && imageIndex >= 1 && imageIndex <= 16,
    'imageIndex must be 1-16.',
  );
  return {
    isoFile: matching(
      input.isoFile,
      isoFilePattern,
      'isoFile must be a plain .iso file name on the build machine.',
    ),
    isoSha256: matching(
      text(input.isoSha256).toLowerCase(),
      sha256Hex,
      'isoSha256 must be the 64-hex SHA-256 of the source ISO.',
    ),
    imageIndex,
    product: matching(
      input.product,
      productPattern,
      "product must look like 'Windows Server 2025'.",
    ),
    templateName: matching(
      input.templateName,
      templateNamePattern,
      'templateName may hold lower-case letters, digits and dashes (2-41).',
    ),
  };
}

export function createOsTemplateBuild({ id, input, requestedBy, now = new Date() }) {
  assertValid(OS_TEMPLATE_BUILD_ID.test(text(id)), 'Invalid OS template build ID.', 500);
  const at = now.toISOString();
  return {
    id,
    status: 'Requested',
    request: validateBuildRequest(input),
    requestedBy: boundedText(requestedBy, 'requestedBy', { max: 200, required: true }),
    createdAt: at,
    updatedAt: at,
    result: null,
    decision: null,
    pipelineRuns: [],
  };
}

// ── Worker result ───────────────────────────────────────────────────────────────

function validateScanSide(value, label) {
  assertValid(isPlainObject(value), `${label} is missing.`);
  return {
    build: matching(
      value.build,
      buildVersionPattern,
      `${label}.build must look like 10.0.26100.33822.`,
    ),
    open: count(value.open, `${label}.open`),
    critical: count(value.critical, `${label}.critical`),
    important: count(value.important, `${label}.important`),
  };
}

function validateUpdates(value) {
  assertValid(
    Array.isArray(value) && value.length <= MAX_UPDATES,
    `updates must list at most ${MAX_UPDATES} files.`,
  );
  return value.map((item) => {
    assertValid(isPlainObject(item), 'Each update must be an object.');
    assertValid(typeof item.applied === 'boolean', 'update.applied must be true or false.');
    return {
      kb: matching(item.kb, /^KB[0-9]{6,8}$/, 'update.kb must look like KB5131080.'),
      file: matching(item.file, msuFilePattern, 'update.file must be an .msu file name.'),
      sha256: matching(text(item.sha256).toLowerCase(), sha256Hex, 'update.sha256 must be 64 hex.'),
      applied: item.applied,
    };
  });
}

function validateArtifact(value) {
  assertValid(
    Array.isArray(value) && value.length === 1,
    'artifacts must list exactly one template ISO.',
  );
  const [item] = value;
  assertValid(isPlainObject(item) && item.format === 'iso', 'The artifact must be an ISO.');
  assertValid(
    Number.isSafeInteger(item.sizeBytes) && item.sizeBytes > 0 && item.sizeBytes <= MAX_ISO_BYTES,
    'artifact.sizeBytes is out of range.',
  );
  return {
    file: matching(item.file, isoFilePattern, 'artifact.file must be an .iso file name.'),
    format: 'iso',
    sizeBytes: item.sizeBytes,
    sha256: matching(text(item.sha256).toLowerCase(), sha256Hex, 'artifact.sha256 must be 64 hex.'),
  };
}

// The template manifest written by Build-WindowsTemplate.ps1, re-shaped to the fields SSI keeps.
function validateManifest(manifest, now) {
  assertValid(isPlainObject(manifest), 'manifest must be a JSON object.');
  assertValid(
    manifest.manifestVersion === OS_TEMPLATE_MANIFEST_VERSION,
    `Unsupported manifest version: ${text(manifest.manifestVersion).slice(0, 64) || 'missing'}.`,
  );
  const { template, build, base, scan } = manifest;
  assertValid(
    isPlainObject(template) && isPlainObject(build) && isPlainObject(base) && isPlainObject(scan),
    'The manifest is incomplete.',
  );
  assertValid(isPlainObject(scan.gate), 'scan.gate is missing.');
  const tools = isPlainObject(build.tools) ? build.tools : {};
  return {
    template: {
      name: matching(template.name, templateNamePattern, 'template.name is invalid.'),
      version: matching(
        template.version,
        /^[0-9]{1,6}\.[0-9]{1,6}$/,
        'template.version must look like 26100.33822.',
      ),
      os: matching(template.os, /^[a-z0-9][a-z0-9.-]{1,40}$/, 'template.os is invalid.'),
      edition: boundedText(template.edition, 'template.edition', { max: 160, required: true }),
      architecture: matching(
        template.architecture,
        /^(amd64|arm64)$/,
        'template.architecture must be amd64 or arm64.',
      ),
    },
    build: {
      id: matching(build.id, workerBuildIdPattern, 'build.id is invalid.'),
      createdAt: isoTimestamp(build.createdAt, 'build.createdAt', now),
      tools: {
        dism: boundedText(tools.dism, 'build.tools.dism', { max: 40 }),
        oscdimg: boundedText(tools.oscdimg, 'build.tools.oscdimg', { max: 40 }),
        powershell: boundedText(tools.powershell, 'build.tools.powershell', { max: 40 }),
      },
    },
    base: {
      file: matching(base.file, isoFilePattern, 'base.file must be an .iso file name.'),
      sha256: matching(text(base.sha256).toLowerCase(), sha256Hex, 'base.sha256 must be 64 hex.'),
      imageIndex: (() => {
        assertValid(
          Number.isInteger(base.imageIndex) && base.imageIndex >= 1 && base.imageIndex <= 16,
          'base.imageIndex must be 1-16.',
        );
        return base.imageIndex;
      })(),
      build: matching(
        base.build,
        buildVersionPattern,
        'base.build must look like 10.0.26100.32230.',
      ),
    },
    updates: validateUpdates(manifest.updates),
    scan: {
      source: boundedText(scan.source, 'scan.source', { max: 200, required: true }),
      before: validateScanSide(scan.before, 'scan.before'),
      after: validateScanSide(scan.after, 'scan.after'),
      gate: {
        maxOpenAfter: count(scan.gate.maxOpenAfter, 'scan.gate.maxOpenAfter'),
        passed: scan.gate.passed === true,
      },
    },
    artifact: validateArtifact(manifest.artifacts),
  };
}

// Windows: the template must come from this request's ISO, edition and name, and must leave no
// CVE open: an image with a known open CVE is never a template, whatever the worker's gate allowed.
function validateWindowsResult(evidence, request, now) {
  const manifest = validateManifest(evidence.manifest, now);
  assertValid(
    manifest.base.sha256 === request.isoSha256,
    'The template was not built from the ISO this request pinned.',
  );
  assertValid(
    manifest.base.imageIndex === request.imageIndex,
    'The template was not built from the requested edition (image index).',
  );
  assertValid(
    manifest.template.name === request.templateName,
    'The template name differs from the request.',
  );
  assertValid(manifest.scan.gate.passed, 'The worker reports that its gate did not pass.');
  assertValid(
    manifest.scan.after.open === 0,
    `${manifest.scan.after.open} CVE(s) are still open in the template; it cannot be recorded as built.`,
  );
  assertValid(
    compareBuilds(manifest.scan.after.build, manifest.base.build) >= 0,
    'The serviced build is older than the source build.',
  );
  const applied = manifest.updates.filter((item) => item.applied);
  assertValid(
    manifest.scan.before.open === 0 ? applied.length === 0 : applied.length === 1,
    'The manifest must name exactly the one update that was applied.',
  );
  const location = isPlainObject(evidence.location) ? evidence.location : {};
  const path = matching(
    location.path,
    windowsPathPattern,
    'location.path must be the template ISO path on the build machine.',
  );
  assertValid(
    path.toLowerCase().endsWith(`\\${manifest.artifact.file.toLowerCase()}`),
    'location.path does not name the template ISO.',
  );
  return {
    manifest,
    location: { host: matching(location.host, hostPattern, 'location.host is invalid.'), path },
  };
}

// Validates an ssi.os-template-build/v1 result for `build` (the request named by the path, the
// signed subject) and returns the result SSI stores, checked by the rules of the request's OS.
export function validateOsTemplateEvidence(
  evidence,
  { build, evidenceDigest, intake, now = Date.now() },
) {
  assertValid(isPlainObject(evidence), 'OS template evidence must be a JSON object.');
  assertValid(
    evidence.contractVersion === OS_TEMPLATE_BUILD_CONTRACT,
    `Unsupported OS template contract: ${text(evidence.contractVersion).slice(0, 64) || 'missing'}.`,
  );
  assertValid(
    build?.id && text(evidence.buildId) === build.id,
    'The result is not for the build request named by the request.',
  );
  const { manifest, location } =
    osTemplateOsOf(build.request) === OS_TEMPLATE_OS.UBUNTU
      ? validateUbuntuResult(evidence, build.request, now)
      : validateWindowsResult(evidence, build.request, now);
  return {
    contractVersion: OS_TEMPLATE_BUILD_CONTRACT,
    generatedAt: isoTimestamp(evidence.generatedAt, 'generatedAt', now),
    evidenceDigest,
    runner: {
      pipeline: boundedText(evidence.runner?.pipeline, 'runner.pipeline', { max: 200 }),
      buildId: boundedText(evidence.runner?.buildId, 'runner.buildId', { max: 64 }),
      agent: boundedText(evidence.runner?.agent, 'runner.agent', { max: 128 }),
    },
    location,
    manifest,
    intake,
  };
}

// ── Ubuntu 24.04 ────────────────────────────────────────────────────────────────

// The same rules as azure-pipelines-os-template-ubuntu.yml and build-ubuntu-template.sh.
const UBUNTU_IMAGE_URL =
  /^https:\/\/cloud-images\.ubuntu\.com\/[A-Za-z0-9._/-]+\/[A-Za-z0-9._-]+\.img$/;
const UBUNTU_MIRROR_URL = /^https?:\/\/[A-Za-z0-9.-]+(:[0-9]{1,5})?(\/[A-Za-z0-9._~/-]*)?$/;
const UBUNTU_FORMATS = Object.freeze({
  qcow2: ['proxmox', 'kvm'],
  ova: ['vmware-vsphere'],
  vhdx: ['hyper-v'],
});
const UBUNTU_GATE_RULE = 'no-fixable-vulnerability-after-patch';
// Where the pipeline publishes the template files (src/lib/osTemplateDownloads.js): one
// artifact per format since 2026-11-25, all three in one artifact before (first runs).
const UBUNTU_LAYOUTS = Object.freeze({
  'os-template-ubuntu-qcow2': 'per-format',
  'os-template-ubuntu-images': 'combined',
});
const templateVersionPattern = /^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$/;
const kernelPattern = /^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-[a-z0-9]+$/;
const adoBuildIdPattern = /^[0-9]{1,12}$/;
const MAX_DISK_IMAGE_BYTES = 256 * 1024 ** 3;
// The worker refuses a Trivy database older than 72 hours; SSI allows some slack, no more.
const MAX_TRIVY_DB_AGE_MS = 7 * 24 * 3600 * 1000;
const SEVERITY_FIELDS = ['total', 'critical', 'high', 'medium', 'low', 'unknown', 'fixable'];

function validateUbuntuRequest(input) {
  const diskSizeGb = Number(input.diskSizeGb ?? 20);
  assertValid(
    Number.isInteger(diskSizeGb) && diskSizeGb >= 10 && diskSizeGb <= 200,
    'diskSizeGb must be a whole number of GiB, 10-200.',
  );
  const baseImageUrl = matching(
    input.baseImageUrl,
    UBUNTU_IMAGE_URL,
    'baseImageUrl must be an official https://cloud-images.ubuntu.com/… .img URL.',
  );
  assertValid(!baseImageUrl.includes('..'), 'baseImageUrl must not contain "..".');
  const aptMirror = text(input.aptMirror);
  assertValid(
    aptMirror === '' || UBUNTU_MIRROR_URL.test(aptMirror),
    'aptMirror must be empty or an http(s) URL without credentials or query.',
  );
  return {
    os: OS_TEMPLATE_OS.UBUNTU,
    baseImageUrl,
    baseImageSha256: matching(
      text(input.baseImageSha256).toLowerCase(),
      sha256Hex,
      'baseImageSha256 must be the 64-hex SHA-256 of the cloud image (its SHA256SUMS).',
    ),
    templateName: matching(
      input.templateName,
      templateNamePattern,
      'templateName may hold lower-case letters, digits and dashes (2-41).',
    ),
    diskSizeGb,
    aptMirror,
  };
}

// Trivy counts (template-report.mjs countBySeverity / countUniqueCves).
function severityCounts(value, label) {
  assertValid(isPlainObject(value), `${label} is missing.`);
  const counts = Object.fromEntries(
    SEVERITY_FIELDS.map((field) => [field, count(value[field], `${label}.${field}`)]),
  );
  assertValid(counts.fixable <= counts.total, `${label}.fixable exceeds ${label}.total.`);
  return counts;
}

function validateUbuntuArtifacts(value, name, version) {
  const formats = Object.keys(UBUNTU_FORMATS);
  assertValid(
    Array.isArray(value) && value.length === formats.length,
    `artifacts must list exactly the ${formats.join(', ')} files.`,
  );
  const artifacts = formats.map((format) => {
    const matches = value.filter((item) => isPlainObject(item) && item.format === format);
    assertValid(matches.length === 1, `artifacts must hold exactly one ${format} file.`);
    const [item] = matches;
    assertValid(
      text(item.file) === `${name}-${version}.${format}`,
      `The ${format} file must be named ${name}-${version}.${format}.`,
    );
    assertValid(
      Number.isSafeInteger(item.sizeBytes) &&
        item.sizeBytes > 0 &&
        item.sizeBytes <= MAX_DISK_IMAGE_BYTES,
      `The size of the ${format} file is out of range.`,
    );
    return {
      file: text(item.file),
      format,
      platforms: [...UBUNTU_FORMATS[format]],
      sizeBytes: item.sizeBytes,
      sha256: matching(
        text(item.sha256).toLowerCase(),
        sha256Hex,
        `The SHA-256 of the ${format} file must be 64 hex.`,
      ),
    };
  });
  return artifacts;
}

// The template manifest of poc/os-template/host/template-report.mjs (buildManifest).
function validateUbuntuManifest(manifest, now) {
  assertValid(isPlainObject(manifest), 'manifest must be a JSON object.');
  assertValid(
    manifest.manifestVersion === OS_TEMPLATE_MANIFEST_VERSION,
    `Unsupported manifest version: ${text(manifest.manifestVersion).slice(0, 64) || 'missing'}.`,
  );
  const { template, build, base, scan } = manifest;
  assertValid(
    isPlainObject(template) && isPlainObject(build) && isPlainObject(base) && isPlainObject(scan),
    'The manifest is incomplete.',
  );
  assertValid(template.os === OS_TEMPLATE_OS.UBUNTU, 'template.os must be ubuntu-24.04.');
  assertValid(template.architecture === 'amd64', 'template.architecture must be amd64.');
  const name = matching(template.name, templateNamePattern, 'template.name is invalid.');
  const version = matching(
    template.version,
    templateVersionPattern,
    'template.version is invalid.',
  );
  const tools = isPlainObject(build.tools) ? build.tools : {};
  const createdAt = isoTimestamp(build.createdAt, 'build.createdAt', now);
  const trivyDbUpdatedAt = isoTimestamp(
    tools.trivyDbUpdatedAt,
    'build.tools.trivyDbUpdatedAt',
    now,
  );
  const dbAge = Date.parse(createdAt) - Date.parse(trivyDbUpdatedAt);
  assertValid(
    dbAge >= -MAX_FUTURE_SKEW_MS && dbAge <= MAX_TRIVY_DB_AGE_MS,
    'The Trivy database of the scan was more than 7 days old when the template was built.',
  );
  assertValid(isPlainObject(scan.gate), 'scan.gate is missing.');
  assertValid(isPlainObject(scan.cves), 'scan.cves is missing (an older worker).');
  assertValid(isPlainObject(scan.kernel), 'scan.kernel is missing.');
  // A scan in which Trivy recognised no operating system reports no OS vulnerability at all.
  assertValid(
    scan.os?.family === 'ubuntu' && scan.os?.name === '24.04',
    'The scan did not recognise the image as Ubuntu 24.04; its vulnerability counts prove nothing.',
  );
  return {
    template: { name, version, os: OS_TEMPLATE_OS.UBUNTU, architecture: 'amd64' },
    build: {
      id: matching(build.id, workerBuildIdPattern, 'build.id is invalid.'),
      createdAt,
      tools: {
        libguestfs: boundedText(tools.libguestfs, 'build.tools.libguestfs', { max: 80 }),
        qemuImg: boundedText(tools['qemu-img'], 'build.tools.qemu-img', { max: 120 }),
        trivy: boundedText(tools.trivy, 'build.tools.trivy', { max: 40, required: true }),
        trivyDbUpdatedAt,
      },
    },
    base: {
      url: matching(base.url, UBUNTU_IMAGE_URL, 'base.url must be the official cloud image URL.'),
      sha256: matching(text(base.sha256).toLowerCase(), sha256Hex, 'base.sha256 must be 64 hex.'),
    },
    scan: {
      scannedAs: 'ubuntu 24.04',
      before: severityCounts(scan.before, 'scan.before'),
      after: severityCounts(scan.after, 'scan.after'),
      cves: {
        before: severityCounts(scan.cves.before, 'scan.cves.before'),
        after: severityCounts(scan.cves.after, 'scan.cves.after'),
      },
      kernel: {
        before: matching(scan.kernel.before, kernelPattern, 'scan.kernel.before is invalid.'),
        after: matching(scan.kernel.after, kernelPattern, 'scan.kernel.after is invalid.'),
      },
      packagesUpgraded: count(scan.packagesUpgraded, 'scan.packagesUpgraded'),
      gate: {
        rule: text(scan.gate.rule),
        enforced: scan.gate.enforced === true,
        passed: scan.gate.passed === true,
      },
    },
    artifacts: validateUbuntuArtifacts(manifest.artifacts, name, version),
  };
}

// Ubuntu: the template must come from this request's cloud image (URL and SHA-256) and name,
// the scan must have seen Ubuntu 24.04, and no CVE with a released fix may remain.
function validateUbuntuResult(evidence, request, now) {
  const manifest = validateUbuntuManifest(evidence.manifest, now);
  assertValid(
    manifest.base.sha256 === request.baseImageSha256,
    'The template was not built from the cloud image this request pinned.',
  );
  assertValid(
    manifest.base.url === request.baseImageUrl,
    'The template was not built from the cloud image URL of this request.',
  );
  assertValid(
    manifest.template.name === request.templateName,
    'The template name differs from the request.',
  );
  const { gate, after, cves } = manifest.scan;
  assertValid(
    gate.rule === UBUNTU_GATE_RULE && gate.enforced && gate.passed,
    'The worker reports that its gate did not pass (or was not enforced).',
  );
  assertValid(
    after.fixable === 0 && cves.after.fixable === 0,
    `${cves.after.fixable || after.fixable} CVE(s) with a released fix are still present; it cannot be recorded as built.`,
  );
  const adoBuildId = matching(
    evidence.runner?.buildId,
    adoBuildIdPattern,
    'runner.buildId must be the Azure DevOps run that holds the template files.',
  );
  const location = isPlainObject(evidence.location) ? evidence.location : {};
  const qcow2 = manifest.artifacts.find((item) => item.format === 'qcow2');
  const path = text(location.path);
  const [artifact, ...rest] = path.split('/');
  const layout = UBUNTU_LAYOUTS[artifact];
  assertValid(
    text(location.host) === 'azure-devops' && layout && rest.join('/') === qcow2.file,
    `location must name ${Object.keys(UBUNTU_LAYOUTS)
      .map((name) => `${name}/${qcow2.file}`)
      .join(' or ')} of the Azure DevOps run.`,
  );
  return {
    manifest,
    location: { host: 'azure-devops', path, artifact, adoBuildId, layout },
  };
}

function ubuntuTemplateFacts(manifest, location) {
  const { scan } = manifest;
  return {
    os: OS_TEMPLATE_OS.UBUNTU,
    name: manifest.template.name,
    version: manifest.template.version,
    edition: 'Ubuntu 24.04 LTS (cloud image)',
    scannedAs: scan.scannedAs,
    kernelBefore: scan.kernel.before,
    kernelAfter: scan.kernel.after,
    packagesUpgraded: scan.packagesUpgraded,
    cvesBefore: scan.cves.before,
    cvesAfter: scan.cves.after,
    findingsBefore: scan.before.total,
    findingsAfter: scan.after.total,
    trivy: {
      version: manifest.build.tools.trivy,
      dbUpdatedAt: manifest.build.tools.trivyDbUpdatedAt,
    },
    base: manifest.base,
    artifacts: manifest.artifacts,
    location: {
      artifact: location.artifact,
      adoBuildId: location.adoBuildId,
      layout: artifactLayoutOf(location),
    },
  };
}

// A replay of the same body is idempotent; a request takes one result, while it is Requested.
export function applyOsTemplateResult(build, result) {
  assertValid(build, 'OS template build request not found.', 404);
  if (build.result?.evidenceDigest && build.result.evidenceDigest === result.evidenceDigest) {
    return { build, changed: false };
  }
  assertValid(
    build.status === 'Requested',
    `This build request is ${build.status}; it takes no new result.`,
    409,
  );
  return {
    build: {
      ...build,
      status: 'Built',
      result,
      updatedAt: result.intake?.receivedAt || new Date().toISOString(),
    },
    changed: true,
  };
}

// ── Decision ────────────────────────────────────────────────────────────────────

// approve: a Built template enters the catalog. reject: closes a Requested or Built request.
// The requester may not decide their own request unless four eyes are disabled.
// `retention`: how the approved template's files are kept (see osTemplateRetention), recorded
// with the approval.
export function decideOsTemplate(
  build,
  { decision, actorId, reason, requireSeparateApprover = true, retention = null, now = new Date() },
) {
  assertValid(build, 'OS template build request not found.', 404);
  assertValid(['approve', 'reject'].includes(decision), 'Unknown decision.', 400);
  const actor = boundedText(actorId, 'actorId', { max: 200, required: true });
  if (decision === 'approve') {
    assertValid(
      build.status === 'Built',
      `Only a built template can be approved (this one is ${build.status}).`,
      409,
    );
  } else {
    assertValid(
      ['Requested', 'Built'].includes(build.status),
      `This build request is already ${build.status}.`,
      409,
    );
  }
  assertValid(
    !requireSeparateApprover || actor.toLowerCase() !== text(build.requestedBy).toLowerCase(),
    'The requester cannot decide their own build request (four eyes).',
    403,
  );
  const at = now.toISOString();
  return {
    ...build,
    status: decision === 'approve' ? 'Approved' : 'Rejected',
    decision: {
      decision,
      by: actor,
      at,
      reason: boundedText(reason, 'reason', { max: 500, required: decision === 'reject' }),
    },
    ...(decision === 'approve' && retention ? { retention } : {}),
    updatedAt: at,
  };
}

// The Azure DevOps run an approved template's files must be retained in, or null when its
// files are not kept in Azure DevOps (Windows: the ISO stays on the build machine).
export function osTemplateRetentionTarget(build) {
  if (osTemplateOsOf(build?.request) !== OS_TEMPLATE_OS.UBUNTU) return null;
  const runId = Number(build?.result?.location?.adoBuildId);
  return Number.isSafeInteger(runId) && runId > 0
    ? { role: 'osTemplateUbuntu', runId, ownerId: `SSI:${build.id}` }
    : null;
}

// The template files a built request produced, for audit records: [{ file, format, sha256 }].
export function osTemplateArtifacts(build) {
  const manifest = build?.result?.manifest;
  if (!manifest) return [];
  const files = manifest.artifacts || (manifest.artifact ? [manifest.artifact] : []);
  return files.map(({ file, format, sha256 }) => ({ file, format, sha256 }));
}

// The audit record of an accepted worker result: { summary, metadata }.
export function osTemplateResultAudit(buildId, result) {
  const { manifest, location } = result;
  const name = `${manifest.template.name} ${manifest.template.version}`;
  if (manifest.template.os === OS_TEMPLATE_OS.UBUNTU) {
    const { cves, kernel } = manifest.scan;
    return {
      summary: `OS template ${name} built for ${buildId}: ${cves.before.fixable} -> ${cves.after.fixable} CVEs with a fix (Trivy, ${cves.after.total} without a released fix)`,
      metadata: {
        evidenceDigest: result.evidenceDigest,
        os: OS_TEMPLATE_OS.UBUNTU,
        baseImageSha256: manifest.base.sha256,
        kernel: `${kernel.before} -> ${kernel.after}`,
        cvesBefore: cves.before.total,
        cvesAfter: cves.after.total,
        fixableBefore: cves.before.fixable,
        fixableAfter: cves.after.fixable,
        artifacts: manifest.artifacts.map(({ file, format, sha256 }) => ({ file, format, sha256 })),
        location: `${location.host}:${location.path} (run ${location.adoBuildId})`,
      },
    };
  }
  return {
    summary: `OS template ${name} built for ${buildId}: ${manifest.scan.before.open} -> ${manifest.scan.after.open} open CVEs`,
    metadata: {
      evidenceDigest: result.evidenceDigest,
      baseBuild: manifest.base.build,
      build: manifest.scan.after.build,
      openBefore: manifest.scan.before.open,
      openAfter: manifest.scan.after.open,
      update: manifest.updates.find((item) => item.applied)?.kb || null,
      isoSha256: manifest.artifact.sha256,
      location: `${location.host}:${location.path}`,
    },
  };
}

// One line for audit records and lists: what the request builds from.
export function describeBuildRequest(request) {
  if (osTemplateOsOf(request) === OS_TEMPLATE_OS.UBUNTU) {
    return `OS template ${request.templateName} (Ubuntu 24.04) requested from ${request.baseImageUrl.split('/').slice(-2).join('/')}`;
  }
  return `OS template ${request.templateName} requested from ${request.isoFile} (index ${request.imageIndex})`;
}

// What the screen and the API show: the record, plus the template facts of a Built one.
export function osTemplateSummary(build) {
  const manifest = build.result?.manifest;
  const os = osTemplateOsOf(build.request);
  return {
    id: build.id,
    os,
    status: build.status,
    request: build.request,
    requestedBy: build.requestedBy,
    createdAt: build.createdAt,
    updatedAt: build.updatedAt,
    decision: build.decision,
    retention: build.retention || null,
    downloads: osTemplateDownloads(build),
    downloadsUnavailable: downloadsUnavailableReason(build),
    template: !manifest
      ? null
      : os === OS_TEMPLATE_OS.UBUNTU
        ? ubuntuTemplateFacts(manifest, build.result.location)
        : {
            os,
            name: manifest.template.name,
            version: manifest.template.version,
            edition: manifest.template.edition,
            baseBuild: manifest.base.build,
            build: manifest.scan.after.build,
            openBefore: manifest.scan.before.open,
            criticalBefore: manifest.scan.before.critical,
            openAfter: manifest.scan.after.open,
            update: manifest.updates.find((item) => item.applied)?.kb || null,
            iso: {
              ...manifest.artifact,
              host: build.result.location.host,
              path: build.result.location.path,
            },
          },
  };
}
