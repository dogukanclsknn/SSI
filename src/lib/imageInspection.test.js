import { describe, expect, it } from 'vitest';
import { CandidateTestError } from './candidateTest.js';
import { CandidateTestValidationError } from './candidateTestEvidence.js';
import {
  applyImageInspection,
  buildImageInspectionEvidence,
  IMAGE_INSPECTION_CONTRACT,
  ImageInspectionError,
  inventoryOf,
  osFamilyOf,
  parseRegistryReference,
  validateImageInspectionEvidence,
} from './imageInspection.js';

const HOST = 'registry.example.com';
const DIGEST = `sha256:${'a'.repeat(64)}`;
const REPOSITORY = `${HOST}/ssi-images/onboarded/nginx`;
const REFERENCE = `${REPOSITORY}@${DIGEST}`;
const NOW = Date.parse('2026-11-11T12:00:00.000Z');

const inspect = (overrides = {}) => [
  {
    RepoDigests: [REFERENCE],
    Os: 'linux',
    Architecture: 'amd64',
    Size: 62_997_887,
    RootFS: { Type: 'layers', Layers: [`sha256:${'1'.repeat(64)}`, `sha256:${'2'.repeat(64)}`] },
    Config: {
      Env: ['PATH=/usr/local/sbin:/usr/bin', 'NGINX_VERSION=1.29.3', 'API_TOKEN=s3cr3t'],
      Cmd: ['nginx', '-g', 'daemon off;'],
      ExposedPorts: { '80/tcp': {} },
      Hostname: 'build-box',
    },
    ...overrides,
  },
];

const trivy = {
  SchemaVersion: 2,
  Metadata: { OS: { Family: 'alpine', Name: '3.22.2' } },
  Results: [
    {
      Class: 'os-pkgs',
      Packages: [
        { Name: 'zlib', Version: '1.3.1-r2', Arch: 'x86_64' },
        { Name: 'curl', Version: '8.23.0-r0', Arch: 'x86_64' },
        { Name: 'musl', Version: '1.2.5-r10', Arch: 'x86_64' },
      ],
    },
  ],
};

const build = (overrides = {}) =>
  buildImageInspectionEvidence({
    reference: REFERENCE,
    image: inspect(),
    trivy,
    runner: { pipeline: 'SSI - Image Inspection', buildId: '42', agent: 'LinuxAgent1' },
    generatedAt: '2026-11-11T11:00:00.000Z',
    ...overrides,
  });

const validate = (evidence, overrides = {}) =>
  validateImageInspectionEvidence(evidence, {
    digest: DIGEST,
    registryHosts: [HOST, 'harbor-api.internal:8443'],
    projects: ['ssi-images'],
    evidenceDigest: `sha256:${'e'.repeat(64)}`,
    intake: { channel: 'worker', workerId: 'LinuxAgent1' },
    now: NOW,
    ...overrides,
  });

describe('image inspection evidence (worker)', () => {
  it('reports the package inventory, layers, size and configuration of one image', () => {
    const evidence = build();
    expect(evidence).toMatchObject({
      contractVersion: IMAGE_INSPECTION_CONTRACT,
      image: { immutableReference: REFERENCE, digest: DIGEST },
      platform: 'linux/amd64',
      os: 'alpine 3.22.2',
      runner: { pipeline: 'SSI - Image Inspection', buildId: '42', agent: 'LinuxAgent1' },
    });
    expect(evidence.packages.map((item) => item.name)).toEqual(['curl', 'musl', 'zlib']);
    expect(evidence.facts).toMatchObject({ sizeBytes: 62_997_887, diffIds: [`sha256:${'1'.repeat(64)}`, `sha256:${'2'.repeat(64)}`] });
  });

  it('keeps environment variable names only and never a value', () => {
    const evidence = build();
    expect(evidence.facts.config.Env).toEqual(['PATH', 'NGINX_VERSION', 'API_TOKEN']);
    expect(evidence.facts.config).not.toHaveProperty('Hostname');
    const serialized = JSON.stringify(evidence);
    for (const value of ['s3cr3t', '1.29.3', '/usr/local/sbin']) expect(serialized).not.toContain(value);
  });

  it('refuses an image that is not the requested digest, or a tag', () => {
    expect(() => build({ image: inspect({ RepoDigests: [`${REPOSITORY}@sha256:${'b'.repeat(64)}`] }) })).toThrow(CandidateTestError);
    expect(() => build({ reference: `${REPOSITORY}:alpine` })).toThrow(CandidateTestError);
  });
});

describe('image inspection intake (SSI)', () => {
  it('stores a bound record keyed like the scan reference', () => {
    const record = validate(build());
    expect(record).toMatchObject({
      reference: `ssi-images/onboarded/nginx@${DIGEST}`,
      registryReference: REFERENCE,
      digest: DIGEST,
      os: 'alpine 3.22.2',
      generatedAt: '2026-11-11T11:00:00.000Z',
      intake: { channel: 'worker' },
    });
    expect(record.packages).toHaveLength(3);
  });

  it('binds the result to the digest of the request, the SSI Harbor host and its projects', () => {
    expect(() => validate(build(), { digest: `sha256:${'b'.repeat(64)}` })).toThrow(/not the digest named by the request/);
    expect(() => validate(build(), { registryHosts: ['harbor.other.example'] })).toThrow(/SSI Harbor registry/);
    expect(() => validate(build(), { registryHosts: [''] })).toThrow(/not configured/);
    expect(() => validate(build(), { projects: ['team-x'] })).toThrow(/not read by SSI/);
    expect(() => validate({ ...build(), image: { immutableReference: `${HOST}/ssi-images/../x@${DIGEST}`, digest: DIGEST } })).toThrow(
      ImageInspectionError,
    );
  });

  it('never accepts an environment variable value, even if a worker sends one', () => {
    const leaking = build();
    leaking.facts.config.Env = ['PATH', 'API_TOKEN=s3cr3t'];
    expect(() => validate(leaking)).toThrow(CandidateTestValidationError);
    expect(() => validate(leaking)).toThrow(/names only/);
  });

  it('rejects malformed packages, a future timestamp and an unknown contract', () => {
    const duplicate = build();
    duplicate.packages.push({ ...duplicate.packages[0] });
    expect(() => validate(duplicate)).toThrow(/listed twice/);
    expect(() => validate({ ...build(), packages: [] })).toThrow(/must list the OS packages/);
    expect(() => validate({ ...build(), packages: [{ name: 'curl', arch: 'x86_64', version: '' }] })).toThrow(/version is required/);
    expect(() => validate({ ...build(), packages: [{ name: 'curl\u001b[31m', arch: '', version: '1' }] })).toThrow(/control characters/);
    expect(() => validate({ ...build(), generatedAt: '2026-11-12T00:00:00.000Z' })).toThrow(/in the future/);
    expect(() => validate({ ...build(), contractVersion: 'ssi.image-inspection/v9' })).toThrow(/Unsupported/);
    expect(() => validate({ ...build(), os: '' })).toThrow(/os is required/);
  });

  it('keeps a replay idempotent and never lets an older result replace a newer one', () => {
    const first = validate(build());
    expect(applyImageInspection(null, first)).toEqual({ record: first, changed: true });
    expect(applyImageInspection(first, { ...first })).toEqual({ record: first, changed: false });
    const newer = { ...first, evidenceDigest: `sha256:${'f'.repeat(64)}`, generatedAt: '2026-11-11T11:30:00.000Z' };
    expect(applyImageInspection(first, newer).changed).toBe(true);
    expect(() => applyImageInspection(newer, { ...first, evidenceDigest: `sha256:${'c'.repeat(64)}` })).toThrow(/newer inspection/);
  });
});

describe('helpers', () => {
  it('parses registry references and refuses path tricks', () => {
    expect(parseRegistryReference(REFERENCE)).toMatchObject({ host: HOST, project: 'ssi-images', reference: `ssi-images/onboarded/nginx@${DIGEST}` });
    expect(parseRegistryReference(`${HOST}/a//b@${DIGEST}`)).toBeNull();
    expect(parseRegistryReference(`${HOST}/a/./b@${DIGEST}`)).toBeNull();
    expect(parseRegistryReference(`${REPOSITORY}:alpine`)).toBeNull();
  });

  it('rebuilds the inventory diffPackages compares and names the OS family', () => {
    const record = validate(build());
    expect(inventoryOf(record).packages.get('curl\u0000x86_64')).toEqual({ name: 'curl', arch: 'x86_64', version: '8.23.0-r0' });
    expect(osFamilyOf(record)).toBe('alpine');
    expect(osFamilyOf({ os: 'debian 12.12' })).toBe('debian');
  });
});
