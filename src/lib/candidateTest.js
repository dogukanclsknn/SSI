// Candidate (pre-release) test of a verified remediation output.
//
// Before a patched image may be published, the candidate test worker
// (azure-pipelines-candidate-test.yml) runs the source and the candidate image side by side
// and checks that the candidate behaves like the source:
//   - image-config      same runtime configuration (Entrypoint, Cmd, Env, ports, ...)
//   - startup           same startup behaviour with the default command (running, or the
//                       same exit code for run-to-completion images); no OOM kill
//   - healthcheck       same health result when the image defines a HEALTHCHECK
//   - package-inventory OS package change report; a removed package fails the test
//
// The evidence also carries image facts of both images for the "What changed" comparison
// (src/lib/imageComparison.js): layer diff IDs, image size and the runtime configuration.
// Environment variables are reported by name only; their values never leave the agent.
//
// This module turns the raw worker observations (docker image/container inspect and Trivy
// package lists) into the ssi.candidate-test/v1 evidence. Pure functions, no I/O:
// scripts/candidate-test.mjs reads the files and delivers the result to SSI, and
// src/lib/candidateTestEvidence.js validates it on the server.

import { changedRuntimeFields } from './imageConfigIntegrity.js';

export const CANDIDATE_TEST_CONTRACT_VERSION = 'ssi.candidate-test/v1';
export const CANDIDATE_TEST_CHECK_IDS = Object.freeze(['image-config', 'startup', 'healthcheck', 'package-inventory']);
export const CANDIDATE_TEST_CHECK_STATUSES = Object.freeze(['pass', 'fail', 'not-applicable']);
export const PACKAGE_CHANGE_TYPES = Object.freeze(['changed', 'added', 'removed']);
export const MAX_PACKAGE_CHANGES = 5000;
export const MAX_IMAGE_LAYERS = 512;
export const MAX_ENV_NAMES = 1000;

// Runtime fields Docker applies when a container starts. Other keys that `docker image
// inspect` may print (Image, Hostname, AttachStdin, ...) are not part of the image contract.
export const RUNTIME_CONFIG_FIELDS = Object.freeze([
  'Cmd',
  'Entrypoint',
  'Env',
  'ExposedPorts',
  'Healthcheck',
  'Labels',
  'OnBuild',
  'Shell',
  'StopSignal',
  'StopTimeout',
  'User',
  'Volumes',
  'WorkingDir',
]);

const immutableReferencePattern = /^[a-z0-9.-]+(?::[0-9]+)?\/[a-z0-9._/-]+@sha256:[a-f0-9]{64}$/;

export class CandidateTestError extends Error {
  constructor(message) {
    super(message);
    this.name = 'CandidateTestError';
  }
}

function assertCandidate(condition, message) {
  if (!condition) throw new CandidateTestError(message);
}

function text(value) {
  return value == null ? '' : String(value).trim();
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

// `docker inspect` prints an array with one object; accept the array or the object.
export function single(document, label) {
  const value = Array.isArray(document) ? document : [document];
  assertCandidate(value.length === 1 && isPlainObject(value[0]), `${label} must describe exactly one object.`);
  return value[0];
}

export function parseImmutableReference(reference, label) {
  const value = text(reference);
  assertCandidate(immutableReferencePattern.test(value), `${label} must be registry/repository@sha256:<digest>.`);
  const at = value.lastIndexOf('@');
  return { reference: value, repository: value.slice(0, at), digest: value.slice(at + 1) };
}

export function platformOfImage(image) {
  return [text(image.Os), text(image.Architecture), text(image.Variant)].filter(Boolean).join('/');
}

// The pulled image must be the exact digest that was requested.
export function assertImageBinding(image, { repository, digest }, label) {
  const repoDigests = Array.isArray(image.RepoDigests) ? image.RepoDigests.map(text) : [];
  assertCandidate(
    repoDigests.includes(`${repository}@${digest}`),
    `The pulled ${label} image is not bound to ${repository}@${digest}.`,
  );
}

function runtimeConfigOf(image) {
  const config = isPlainObject(image.Config) ? image.Config : {};
  return {
    os: text(image.Os),
    architecture: text(image.Architecture),
    config: Object.fromEntries(RUNTIME_CONFIG_FIELDS.filter((key) => key in config).map((key) => [key, config[key]])),
  };
}

// "NAME=value" -> "NAME". The value is dropped here, before the evidence is written.
export function envNameOf(entry) {
  const value = text(entry);
  const equals = value.indexOf('=');
  return equals === -1 ? value : value.slice(0, equals);
}

// Comparison facts of one image from `docker image inspect`. Layers are the RootFS diff IDs
// (uncompressed content digests), so source and candidate are compared on the same basis.
// Informational: a missing layer list or size is reported as empty and never fails the test.
export function imageFactsOf(image, label = 'image') {
  const diffIds = Array.isArray(image.RootFS?.Layers) ? image.RootFS.Layers.map(text) : [];
  assertCandidate(diffIds.length <= MAX_IMAGE_LAYERS, `The ${label} image has more than ${MAX_IMAGE_LAYERS} layers.`);
  const { config } = runtimeConfigOf(image);
  if (Array.isArray(config.Env)) {
    config.Env = config.Env.map(envNameOf).filter(Boolean);
    assertCandidate(config.Env.length <= MAX_ENV_NAMES, `The ${label} image defines more than ${MAX_ENV_NAMES} environment variables.`);
  }
  return {
    sizeBytes: Number.isSafeInteger(image.Size) && image.Size >= 0 ? image.Size : null,
    diffIds,
    config,
  };
}

function hasHealthcheck(image) {
  const test = image.Config?.Healthcheck?.Test;
  return Array.isArray(test) && test.length > 0 && test[0] !== 'NONE';
}

// --- Packages ---------------------------------------------------------------------------

function packageVersion(pkg) {
  const epoch = Number(pkg.Epoch) > 0 ? `${Number(pkg.Epoch)}:` : '';
  const release = text(pkg.Release);
  return `${epoch}${text(pkg.Version)}${release ? `-${release}` : ''}`;
}

// OS packages from a Trivy JSON report (SchemaVersion 2, list-all-pkgs). Keyed by name and
// architecture so multi-arch Debian packages are kept apart.
export function packageInventoryOf(report, label = 'image') {
  assertCandidate(isPlainObject(report) && Number(report.SchemaVersion) === 2, `The ${label} Trivy report must be SchemaVersion 2.`);
  const osResults = (Array.isArray(report.Results) ? report.Results : []).filter((result) => result?.Class === 'os-pkgs');
  assertCandidate(osResults.length > 0, `Trivy detected no OS packages in the ${label} image.`);

  const packages = new Map();
  for (const result of osResults) {
    for (const pkg of Array.isArray(result.Packages) ? result.Packages : []) {
      const name = text(pkg?.Name);
      const version = packageVersion(pkg || {});
      if (!name || !version) continue;
      const arch = text(pkg.Arch);
      const key = `${name}\u0000${arch}`;
      const existing = packages.get(key);
      // A duplicate entry for the same name/arch is unusual; keep every version so a later
      // difference is still visible instead of silently dropping one.
      const versions = existing ? [...new Set([...existing.version.split(', '), version])].sort() : [version];
      packages.set(key, { name, arch, version: versions.join(', ') });
    }
  }
  return {
    os: [text(report.Metadata?.OS?.Family), text(report.Metadata?.OS?.Name)].filter(Boolean).join(' '),
    packages,
  };
}

// Epoch and first numeric component of a distro version ("1:2.3-4" -> "1:2", "8.23.0-r0" -> "0:8").
function majorVersionOf(version) {
  const value = text(version);
  const colon = value.indexOf(':');
  const epoch = colon > 0 && /^\d+$/.test(value.slice(0, colon)) ? value.slice(0, colon) : '0';
  const rest = colon > 0 ? value.slice(colon + 1) : value;
  const major = rest.match(/\d+/)?.[0] ?? rest;
  return `${epoch}:${major}`;
}

export function diffPackages(sourceInventory, candidateInventory) {
  const keys = [...new Set([...sourceInventory.packages.keys(), ...candidateInventory.packages.keys()])].sort();
  const changes = [];
  let unchanged = 0;
  for (const key of keys) {
    const from = sourceInventory.packages.get(key);
    const to = candidateInventory.packages.get(key);
    if (from && to && from.version === to.version) {
      unchanged += 1;
      continue;
    }
    const change = !from ? 'added' : !to ? 'removed' : 'changed';
    const item = from || to;
    changes.push({
      name: item.name,
      arch: item.arch,
      from: from?.version || '',
      to: to?.version || '',
      change,
      majorVersionChange: change === 'changed' && majorVersionOf(from.version) !== majorVersionOf(to.version),
    });
  }
  assertCandidate(changes.length <= MAX_PACKAGE_CHANGES, `More than ${MAX_PACKAGE_CHANGES} package changes; refusing to report.`);
  return {
    summary: {
      unchanged,
      changed: changes.filter((item) => item.change === 'changed').length,
      added: changes.filter((item) => item.change === 'added').length,
      removed: changes.filter((item) => item.change === 'removed').length,
      majorVersionChanges: changes.filter((item) => item.majorVersionChange).length,
    },
    changes,
  };
}

// The package inventory check fails only on a removed package: a security patch must never
// take software away from the image. Added packages (new dependencies) and major version
// changes are reported for the consumer team to review.
export function packageInventoryStatus(summary) {
  return summary.removed > 0 ? 'fail' : 'pass';
}

// --- Containers -------------------------------------------------------------------------

export function startupObservationOf(container, label = 'container') {
  const state = single(container, `The ${label} inspect output`).State;
  assertCandidate(isPlainObject(state), `The ${label} inspect output has no State.`);
  const status = text(state.Status);
  return {
    state: status === 'running' ? 'running' : status === 'exited' ? 'exited' : status || 'unknown',
    exitCode: Number.isInteger(state.ExitCode) ? state.ExitCode : null,
    oomKilled: state.OOMKilled === true,
    restarting: state.Restarting === true,
    health: text(state.Health?.Status) || 'none',
  };
}

function describe(observation) {
  const base =
    observation.state === 'exited'
      ? `exited with code ${observation.exitCode}`
      : observation.state === 'not-started'
        ? 'could not be started'
        : observation.state;
  return observation.oomKilled ? `${base} (OOM killed)` : base;
}

export function startupCheck(source, candidate) {
  const sameRunning = source.state === 'running' && candidate.state === 'running';
  const sameExit = source.state === 'exited' && candidate.state === 'exited' && source.exitCode === candidate.exitCode;
  // An image without a default command cannot start on its own; that is only acceptable
  // when the source cannot either (the candidate must not lose its command).
  const neitherStarts = source.state === 'not-started' && candidate.state === 'not-started';
  const passed = !candidate.oomKilled && !candidate.restarting && (sameRunning || sameExit || neitherStarts);
  let detail = `Startup differs: source ${describe(source)}, candidate ${describe(candidate)}.`;
  if (neitherStarts) detail = 'Neither image starts on its own (no default command); behaviour is unchanged.';
  else if (passed) detail = `Candidate starts like the source with its default command (${describe(candidate)}).`;
  return { id: 'startup', status: passed ? 'pass' : 'fail', detail };
}

export function healthcheckCheck({ sourceDefinesHealthcheck, candidateDefinesHealthcheck }, source, candidate) {
  if (!sourceDefinesHealthcheck && !candidateDefinesHealthcheck) {
    return { id: 'healthcheck', status: 'not-applicable', detail: 'Neither image defines a HEALTHCHECK.' };
  }
  const settled = !['starting', 'none'].includes(candidate.health) && !['starting', 'none'].includes(source.health);
  const passed = settled && candidate.health === source.health;
  return {
    id: 'healthcheck',
    status: passed ? 'pass' : 'fail',
    detail: passed
      ? `Health result matches the source (${candidate.health}).`
      : `Health result differs or did not settle: source ${source.health}, candidate ${candidate.health}.`,
  };
}

// --- Evidence ---------------------------------------------------------------------------

export function deriveCandidateTestPassed(checks) {
  return CANDIDATE_TEST_CHECK_IDS.every((id) => {
    const check = checks.find((item) => item.id === id);
    return check && (check.status === 'pass' || (id === 'healthcheck' && check.status === 'not-applicable'));
  });
}

export function buildCandidateTestEvidence({
  jobId,
  sourceReference,
  candidateReference,
  sourceImage,
  candidateImage,
  sourceContainer,
  candidateContainer,
  sourceTrivy,
  candidateTrivy,
  runner = {},
  generatedAt = new Date().toISOString(),
}) {
  assertCandidate(/^RM-EXEC-[0-9]{4,}$/.test(text(jobId)), 'The job ID must identify an RM-EXEC job.');
  const source = parseImmutableReference(sourceReference, 'The source reference');
  const candidate = parseImmutableReference(candidateReference, 'The candidate reference');
  assertCandidate(source.digest !== candidate.digest, 'The candidate digest must differ from the source digest.');

  const sourceImageInfo = single(sourceImage, 'The source image inspect output');
  const candidateImageInfo = single(candidateImage, 'The candidate image inspect output');
  assertImageBinding(sourceImageInfo, source, 'source');
  assertImageBinding(candidateImageInfo, candidate, 'candidate');
  const platform = platformOfImage(candidateImageInfo);
  assertCandidate(platform && platform === platformOfImage(sourceImageInfo), 'The source and candidate images must have the same platform.');

  const changedFields = changedRuntimeFields(runtimeConfigOf(sourceImageInfo), runtimeConfigOf(candidateImageInfo));
  const sourceStartup = startupObservationOf(sourceContainer, 'source container');
  const candidateStartup = startupObservationOf(candidateContainer, 'candidate container');
  const packageChanges = diffPackages(packageInventoryOf(sourceTrivy, 'source'), packageInventoryOf(candidateTrivy, 'candidate'));
  const { summary } = packageChanges;

  const checks = [
    {
      id: 'image-config',
      status: changedFields.length === 0 ? 'pass' : 'fail',
      detail:
        changedFields.length === 0
          ? 'Runtime configuration is identical to the source.'
          : `Runtime configuration differs from the source: ${changedFields.join(', ')}.`,
    },
    startupCheck(sourceStartup, candidateStartup),
    healthcheckCheck(
      { sourceDefinesHealthcheck: hasHealthcheck(sourceImageInfo), candidateDefinesHealthcheck: hasHealthcheck(candidateImageInfo) },
      sourceStartup,
      candidateStartup,
    ),
    {
      id: 'package-inventory',
      status: packageInventoryStatus(summary),
      detail:
        `${summary.changed} changed, ${summary.added} added, ${summary.removed} removed, ` +
        `${summary.majorVersionChanges} major version change(s), ${summary.unchanged} unchanged.` +
        (summary.removed > 0 ? ' A security patch must not remove packages.' : ''),
    },
  ];

  return {
    contractVersion: CANDIDATE_TEST_CONTRACT_VERSION,
    generatedAt,
    remediationJobId: text(jobId),
    source: { immutableReference: source.reference, digest: source.digest },
    candidate: { immutableReference: candidate.reference, digest: candidate.digest },
    platform,
    runner: {
      pipeline: text(runner.pipeline).slice(0, 200),
      buildId: text(runner.buildId).slice(0, 64),
      agent: text(runner.agent).slice(0, 128),
    },
    startup: { source: sourceStartup, candidate: candidateStartup },
    checks,
    packageChanges,
    imageFacts: { source: imageFactsOf(sourceImageInfo, 'source'), candidate: imageFactsOf(candidateImageInfo, 'candidate') },
    passed: deriveCandidateTestPassed(checks),
  };
}
