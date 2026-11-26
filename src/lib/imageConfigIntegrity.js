// Image configuration integrity for Copa remediation outputs.
//
// Copa patches OS packages by adding a layer; it must not change how the image starts or
// runs. The Copa BuildKit frontend output can lose the source image's runtime
// configuration (Entrypoint, Cmd, ExposedPorts, StopSignal, ...), and a vulnerability
// re-scan cannot detect that. These functions compare the runtime configuration of the
// source and patched image configs and plan a metadata-only restore: the patched config
// keeps its own rootfs, history and platform, and only its runtime "config" section is
// replaced with the source's. No layer changes.
//
// Pure functions, no I/O: scripts/image-config-integrity.mjs reads the registry
// documents, hashes bytes and writes files.

export const CONFIG_INTEGRITY_CONTRACT_VERSION = 'ssi.image-config-integrity/v1';
export const CONFIG_INTEGRITY_STATUSES = Object.freeze(['preserved', 'restored']);

const OCI_INDEX = 'application/vnd.oci.image.index.v1+json';
const DOCKER_MANIFEST_LIST = 'application/vnd.docker.distribution.manifest.list.v2+json';
const OCI_MANIFEST = 'application/vnd.oci.image.manifest.v1+json';
const DOCKER_MANIFEST = 'application/vnd.docker.distribution.manifest.v2+json';
const DOCKER_CONFIG = 'application/vnd.docker.container.image.v1+json';
const ATTESTATION_REFERENCE_TYPE = 'attestation-manifest';
const digestPattern = /^sha256:[a-f0-9]{64}$/;

export class ImageConfigIntegrityError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ImageConfigIntegrityError';
  }
}

function assertIntegrity(condition, message) {
  if (!condition) throw new ImageConfigIntegrityError(message);
}

function text(value) {
  return value == null ? '' : String(value).trim();
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

// A field that is absent, null, empty or false has no runtime effect, so "Cmd": null and
// a missing Cmd are the same configuration.
function hasRuntimeEffect(value) {
  if (value == null || value === '' || value === false) return false;
  if (Array.isArray(value)) return value.length > 0;
  if (isPlainObject(value)) return Object.keys(value).length > 0;
  return true;
}

// Sorted object keys, array order kept: equal configurations serialize identically.
export function canonicalJson(value) {
  const canonicalize = (item) => {
    if (Array.isArray(item)) return item.map(canonicalize);
    if (isPlainObject(item)) {
      return Object.fromEntries(
        Object.keys(item)
          .sort()
          .map((key) => [key, canonicalize(item[key])]),
      );
    }
    return item;
  };
  return JSON.stringify(canonicalize(value));
}

function assertImageConfig(imageConfig, label) {
  assertIntegrity(isPlainObject(imageConfig), `The ${label} image config must be a JSON object.`);
  assertIntegrity(
    imageConfig.config == null || isPlainObject(imageConfig.config),
    `The ${label} image config has an invalid runtime "config" section.`,
  );
}

// The runtime section of an OCI/Docker image config, without fields that have no effect.
export function runtimeConfigOf(imageConfig, label = 'image') {
  assertImageConfig(imageConfig, label);
  const config = imageConfig.config || {};
  return Object.fromEntries(
    Object.keys(config)
      .sort()
      .filter((key) => hasRuntimeEffect(config[key]))
      .map((key) => [key, config[key]]),
  );
}

// Names of the runtime fields (Cmd, Entrypoint, Env, ...) whose values differ.
export function changedRuntimeFields(sourceConfig, outputConfig) {
  const source = runtimeConfigOf(sourceConfig, 'source');
  const output = runtimeConfigOf(outputConfig, 'output');
  return [...new Set([...Object.keys(source), ...Object.keys(output)])]
    .sort()
    .filter((key) => canonicalJson(source[key] ?? null) !== canonicalJson(output[key] ?? null));
}

function platformString({ os, architecture, variant }) {
  return [text(os), text(architecture), text(variant)].filter(Boolean).join('/');
}

// "os/architecture[/variant]" of an image config, e.g. linux/amd64 or linux/arm64/v8.
export function platformOf(imageConfig, label = 'image') {
  assertImageConfig(imageConfig, label);
  assertIntegrity(
    text(imageConfig.os) && text(imageConfig.architecture),
    `The ${label} image config does not declare its os and architecture.`,
  );
  return platformString(imageConfig);
}

function isIndex(manifest) {
  return [OCI_INDEX, DOCKER_MANIFEST_LIST].includes(manifest.mediaType) || Array.isArray(manifest.manifests);
}

function isAttestation(descriptor) {
  return (
    descriptor.annotations?.['vnd.docker.reference.type'] === ATTESTATION_REFERENCE_TYPE ||
    (descriptor.platform?.os === 'unknown' && descriptor.platform?.architecture === 'unknown')
  );
}

function assertManifest(manifest) {
  assertIntegrity(
    isPlainObject(manifest) && manifest.schemaVersion === 2,
    'Only schemaVersion 2 image manifests and indexes are supported.',
  );
}

// Resolves a manifest or index to its single runnable image manifest. Returns the image
// manifest digest, or null when the document already is that image manifest. Attestation
// manifests are skipped; more than one candidate is refused (fail-closed), because a
// partial check of a multi-platform output would not prove anything about the others.
export function selectImageManifest(manifest, platform = '') {
  assertManifest(manifest);
  if (!isIndex(manifest)) {
    assertIntegrity(isPlainObject(manifest.config), 'The image manifest does not reference a config blob.');
    return null;
  }

  const images = manifest.manifests.filter((descriptor) => isPlainObject(descriptor) && !isAttestation(descriptor));
  const wanted = text(platform);
  const candidates = wanted
    ? images.filter((descriptor) => platformString(descriptor.platform || {}) === wanted)
    : images;
  assertIntegrity(
    candidates.length === 1,
    wanted
      ? `Expected exactly one ${wanted} image in the index, found ${candidates.length}.`
      : `Expected exactly one platform image in the remediation output, found ${candidates.length}. Multi-platform outputs are not supported.`,
  );
  const digest = text(candidates[0].digest);
  assertIntegrity(digestPattern.test(digest), 'The selected image manifest digest is not a sha256 digest.');
  return digest;
}

export function configDigestOf(imageManifest) {
  assertManifest(imageManifest);
  assertIntegrity(!isIndex(imageManifest), 'A platform image manifest is required, not an index.');
  const digest = text(imageManifest.config?.digest);
  assertIntegrity(digestPattern.test(digest), 'The image manifest config digest is not a sha256 digest.');
  return digest;
}

export function layerDigestsOf(imageManifest) {
  assertManifest(imageManifest);
  assertIntegrity(Array.isArray(imageManifest.layers), 'The image manifest does not list its layers.');
  return imageManifest.layers.map((layer) => text(layer?.digest));
}

// Content type to push the restored manifest with: the patched manifest's own media type.
export function manifestMediaTypeOf(imageManifest) {
  if (text(imageManifest.mediaType)) return text(imageManifest.mediaType);
  return imageManifest.config?.mediaType === DOCKER_CONFIG ? DOCKER_MANIFEST : OCI_MANIFEST;
}

// Compares the source and patched configs. When they differ, returns the restored config:
// the patched config (rootfs, history, platform, created) with the source runtime section.
export function planConfigRestore({ sourceConfig, outputConfig }) {
  const sourcePlatform = platformOf(sourceConfig, 'source');
  const outputPlatform = platformOf(outputConfig, 'output');
  assertIntegrity(
    sourcePlatform === outputPlatform,
    `The patched image platform (${outputPlatform}) does not match the source platform (${sourcePlatform}).`,
  );

  const changedFields = changedRuntimeFields(sourceConfig, outputConfig);
  if (changedFields.length === 0) {
    return { status: 'preserved', platform: outputPlatform, changedFields, restoredConfig: null };
  }

  const restoredConfig = { ...outputConfig };
  if (sourceConfig.config == null) {
    delete restoredConfig.config;
  } else {
    restoredConfig.config = JSON.parse(JSON.stringify(sourceConfig.config));
  }
  return { status: 'restore-required', platform: outputPlatform, changedFields, restoredConfig };
}

// The patched image manifest pointing at the restored config; the layers are untouched.
export function restoredImageManifest(outputManifest, { digest, size }) {
  assertManifest(outputManifest);
  assertIntegrity(!isIndex(outputManifest), 'A platform image manifest is required, not an index.');
  assertIntegrity(digestPattern.test(text(digest)), 'The restored config digest is not a sha256 digest.');
  assertIntegrity(Number.isInteger(size) && size > 0, 'The restored config size must be a positive integer.');
  return { ...outputManifest, config: { ...outputManifest.config, digest, size } };
}
