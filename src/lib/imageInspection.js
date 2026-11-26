// SSI — Image inspection: the facts of one scanned image that a vulnerability scan does not
// carry, for the free comparison of two images (Scan Results → "Compare with another image").
//
// The "SSI - Image Inspection" worker (azure-pipelines-image-inspection.yml) pulls one image by
// digest and reports, as ssi.image-inspection/v1:
//   - the full OS package inventory (Trivy package list, no vulnerability database)
//   - the layers (RootFS diff IDs), the image size and the runtime configuration
// It never starts a container. Environment variables are reported by name only: the value is
// dropped on the agent, and SSI refuses any entry that still carries one.
//
// An image is inspected once and can then be compared with any other inspected image.
// Pure functions, no I/O: scripts/image-inspection.mjs builds and delivers the evidence,
// server.js validates and stores it (src/server/imageInspectionStore.js).

import {
  assertImageBinding,
  imageFactsOf,
  packageInventoryOf,
  parseImmutableReference,
  platformOfImage,
  single,
} from './candidateTest.js';
import { validateImageSide } from './candidateTestEvidence.js';

export const IMAGE_INSPECTION_CONTRACT = 'ssi.image-inspection/v1';
export const MAX_INVENTORY_PACKAGES = 10000;

const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;
const sha256Pattern = /^sha256:[a-f0-9]{64}$/;
const platformPattern = /^[a-z0-9]+\/[a-z0-9_]+(?:\/[a-z0-9]+)?$/;
// registry/project/repository@sha256:<digest>; the registry is the Harbor host.
const registryReferencePattern = /^([a-z0-9.-]+(?::[0-9]+)?)\/([a-z0-9][a-z0-9._/-]*)@(sha256:[a-f0-9]{64})$/;

export class ImageInspectionError extends Error {
  constructor(message, statusCode = 422) {
    super(message);
    this.name = 'ImageInspectionError';
    this.statusCode = statusCode;
  }
}

function assertValid(condition, message, statusCode) {
  if (!condition) throw new ImageInspectionError(message, statusCode);
}

function text(value) {
  return value == null ? '' : String(value).trim();
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

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

const byNameAndArch = (left, right) => left.name.localeCompare(right.name) || left.arch.localeCompare(right.arch);

// ── Worker side ─────────────────────────────────────────────────────────────────

// image: `docker image inspect` output of the pulled digest; trivy: Trivy JSON (SchemaVersion 2,
// license scanner, OS packages). Throws CandidateTestError on unusable input.
export function buildImageInspectionEvidence({
  reference,
  image,
  trivy,
  runner = {},
  generatedAt = new Date().toISOString(),
}) {
  const parsed = parseImmutableReference(reference, 'The image reference');
  const info = single(image, 'The image inspect output');
  assertImageBinding(info, parsed, 'inspected');
  const platform = platformOfImage(info);
  assertValid(platform, 'The image inspect output does not name its platform.');
  const inventory = packageInventoryOf(trivy, 'inspected');
  const packages = [...inventory.packages.values()].sort(byNameAndArch);
  assertValid(packages.length <= MAX_INVENTORY_PACKAGES, `More than ${MAX_INVENTORY_PACKAGES} OS packages; refusing to report.`);
  return {
    contractVersion: IMAGE_INSPECTION_CONTRACT,
    generatedAt,
    image: { immutableReference: parsed.reference, digest: parsed.digest },
    platform,
    os: inventory.os,
    runner: {
      pipeline: text(runner.pipeline).slice(0, 200),
      buildId: text(runner.buildId).slice(0, 64),
      agent: text(runner.agent).slice(0, 128),
    },
    packages,
    facts: imageFactsOf(info, 'inspected'),
  };
}

// ── SSI side ────────────────────────────────────────────────────────────────────

// "<registry>/<project>/<repository>@sha256:…" split into its parts; null when malformed.
export function parseRegistryReference(value) {
  const match = registryReferencePattern.exec(text(value).toLowerCase());
  if (!match) return null;
  const [, host, path, digest] = match;
  if (path.split('/').some((segment) => !segment || segment === '.' || segment === '..')) return null;
  return { host, path, digest, project: path.split('/')[0], reference: `${path}@${digest}` };
}

function validatePackages(value) {
  assertValid(Array.isArray(value) && value.length > 0, 'packages must list the OS packages of the image.');
  assertValid(value.length <= MAX_INVENTORY_PACKAGES, `packages must list at most ${MAX_INVENTORY_PACKAGES} entries.`);
  const seen = new Set();
  const packages = value.map((item) => {
    assertValid(isPlainObject(item), 'Each package must be an object.');
    const name = boundedText(item.name, 'Package name', { max: 200, required: true });
    const arch = boundedText(item.arch, `Package ${name} architecture`, { max: 64 });
    const version = boundedText(item.version, `Package ${name} version`, { max: 200, required: true });
    const key = `${name}\u0000${arch}`;
    assertValid(!seen.has(key), `Package ${name} (${arch || 'no arch'}) is listed twice.`);
    seen.add(key);
    return { name, arch, version };
  });
  return packages.sort(byNameAndArch);
}

function isoTimestamp(value, label, now) {
  const normalized = text(value);
  const time = Date.parse(normalized);
  assertValid(normalized && Number.isFinite(time), `${label} must be an ISO-8601 timestamp.`);
  assertValid(time <= now + MAX_FUTURE_SKEW_MS, `${label} is in the future.`);
  return new Date(time).toISOString();
}

// Validates an ssi.image-inspection/v1 result and returns the record SSI stores.
//   digest        the digest named by the request path (the signed subject)
//   registryHosts the hosts of the SSI Harbor (registry names and the API host)
//   projects      the Harbor projects SSI reads
export function validateImageInspectionEvidence(
  evidence,
  { digest, registryHosts = [], projects = [], evidenceDigest, intake, now = Date.now() },
) {
  assertValid(isPlainObject(evidence), 'Image inspection evidence must be a JSON object.');
  assertValid(
    evidence.contractVersion === IMAGE_INSPECTION_CONTRACT,
    `Unsupported image inspection contract: ${text(evidence.contractVersion).slice(0, 64) || 'missing'}.`,
  );
  const target = parseRegistryReference(evidence.image?.immutableReference);
  assertValid(target, 'image.immutableReference must be <registry>/<project>/<repository>@sha256:<64 hex>.');
  assertValid(sha256Pattern.test(text(digest)), 'The request does not name an image digest.', 400);
  assertValid(
    target.digest === text(digest) && text(evidence.image?.digest).toLowerCase() === target.digest,
    'The inspected image is not the digest named by the request.',
  );
  const hosts = registryHosts.map((item) => text(item).toLowerCase()).filter(Boolean);
  assertValid(
    hosts.includes(target.host),
    `Only images in the SSI Harbor registry (${hosts.join(', ') || 'not configured'}) can be inspected.`,
  );
  assertValid(
    projects.map((item) => text(item).toLowerCase()).includes(target.project),
    `Harbor project ${target.project} is not read by SSI.`,
  );
  const platform = text(evidence.platform);
  assertValid(platformPattern.test(platform), 'The inspected platform is invalid.');

  return {
    contractVersion: IMAGE_INSPECTION_CONTRACT,
    reference: target.reference,
    registryReference: `${target.host}/${target.reference}`,
    digest: target.digest,
    generatedAt: isoTimestamp(evidence.generatedAt, 'generatedAt', now),
    evidenceDigest,
    platform,
    os: boundedText(evidence.os, 'os', { max: 120, required: true }),
    runner: {
      pipeline: boundedText(evidence.runner?.pipeline, 'runner.pipeline', { max: 200 }),
      buildId: boundedText(evidence.runner?.buildId, 'runner.buildId', { max: 64 }),
      agent: boundedText(evidence.runner?.agent, 'runner.agent', { max: 128 }),
    },
    packages: validatePackages(evidence.packages),
    // Same rules as the candidate test facts: Env names only, bounded layers and config.
    facts: validateImageSide(evidence.facts, 'facts'),
    intake,
  };
}

// A replay of the same body is idempotent; an older result never replaces a newer one.
export function applyImageInspection(current, record) {
  if (current?.evidenceDigest && current.evidenceDigest === record.evidenceDigest) {
    return { record: current, changed: false };
  }
  assertValid(
    !current || Date.parse(record.generatedAt) > Date.parse(current.generatedAt),
    'A newer inspection of this image is already recorded.',
    409,
  );
  return { record, changed: true };
}

// The stored package list as the inventory diffPackages (candidateTest.js) compares.
export function inventoryOf(record) {
  const packages = new Map();
  for (const item of Array.isArray(record?.packages) ? record.packages : []) {
    packages.set(`${item.name}\u0000${item.arch}`, { name: item.name, arch: item.arch, version: item.version });
  }
  return { os: text(record?.os), packages };
}

// "alpine 3.22.2" -> "alpine"; the family decides whether two images are comparable.
export function osFamilyOf(record) {
  return text(record?.os).split(/\s+/)[0].toLowerCase();
}
