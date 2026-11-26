import { describe, expect, it } from 'vitest';
import {
  buildCandidateTestEvidence,
  CandidateTestError,
  diffPackages,
  envNameOf,
  healthcheckCheck,
  packageInventoryOf,
  parseImmutableReference,
  startupCheck,
  startupObservationOf,
} from './candidateTest.js';

const SOURCE_DIGEST = `sha256:${'a'.repeat(64)}`;
const CANDIDATE_DIGEST = `sha256:${'b'.repeat(64)}`;
const REPOSITORY = 'registry.example.com/ssi-images/onboarded/nginx';
const SOURCE_REF = `${REPOSITORY}@${SOURCE_DIGEST}`;
const CANDIDATE_REF = `${REPOSITORY}@${CANDIDATE_DIGEST}`;

// `docker image inspect` output (array with one image).
const BASE_LAYERS = [`sha256:${'1'.repeat(64)}`, `sha256:${'2'.repeat(64)}`];
const PATCH_LAYER = `sha256:${'3'.repeat(64)}`;

function imageInspect(digest, configOverrides = {}, { layers = BASE_LAYERS, size = 48_000_000 } = {}) {
  return [
    {
      RepoDigests: [`${REPOSITORY}@${digest}`],
      Os: 'linux',
      Architecture: 'amd64',
      Size: size,
      RootFS: { Type: 'layers', Layers: layers },
      Config: {
        Image: digest, // differs per image; not part of the runtime contract
        Hostname: '',
        Env: ['PATH=/usr/sbin:/usr/bin', 'NGINX_VERSION=1.31.0'],
        Entrypoint: ['/docker-entrypoint.sh'],
        Cmd: ['nginx', '-g', 'daemon off;'],
        ExposedPorts: { '80/tcp': {} },
        StopSignal: 'SIGQUIT',
        ...configOverrides,
      },
    },
  ];
}

// `docker inspect` output of a container.
function containerInspect(state) {
  return [{ State: { Status: 'running', ExitCode: 0, OOMKilled: false, Restarting: false, ...state } }];
}

function trivyReport(packages) {
  return {
    SchemaVersion: 2,
    Metadata: { OS: { Family: 'alpine', Name: '3.22.1' } },
    Results: [
      {
        Class: 'os-pkgs',
        Type: 'alpine',
        Packages: packages.map(([Name, Version, extra = {}]) => ({ Name, Version, Arch: 'x86_64', ...extra })),
      },
    ],
  };
}

const sourcePackages = [
  ['musl', '1.2.5-r10'],
  ['curl', '8.22.0-r0'],
  ['zlib', '1.3.1-r2'],
];
const candidatePackages = [
  ['musl', '1.2.5-r10'],
  ['curl', '8.23.0-r0'],
  ['zlib', '2.0.0-r0'],
  ['libidn2', '2.3.7-r0'],
];

function build(overrides = {}) {
  return buildCandidateTestEvidence({
    jobId: 'RM-EXEC-0004',
    sourceReference: SOURCE_REF,
    candidateReference: CANDIDATE_REF,
    sourceImage: imageInspect(SOURCE_DIGEST),
    candidateImage: imageInspect(CANDIDATE_DIGEST),
    sourceContainer: containerInspect({}),
    candidateContainer: containerInspect({}),
    sourceTrivy: trivyReport(sourcePackages),
    candidateTrivy: trivyReport(candidatePackages),
    runner: { pipeline: 'SSI - Candidate Test', buildId: '901', agent: 'LinuxAgent1' },
    generatedAt: '2026-11-04T10:00:00.000Z',
    ...overrides,
  });
}

describe('candidate test evidence', () => {
  it('passes a candidate that behaves like the source and reports package changes', () => {
    const evidence = build();

    expect(evidence).toMatchObject({
      contractVersion: 'ssi.candidate-test/v1',
      remediationJobId: 'RM-EXEC-0004',
      platform: 'linux/amd64',
      source: { immutableReference: SOURCE_REF, digest: SOURCE_DIGEST },
      candidate: { immutableReference: CANDIDATE_REF, digest: CANDIDATE_DIGEST },
      passed: true,
    });
    expect(evidence.checks.map((check) => [check.id, check.status])).toEqual([
      ['image-config', 'pass'],
      ['startup', 'pass'],
      ['healthcheck', 'not-applicable'],
      ['package-inventory', 'pass'],
    ]);
    expect(evidence.packageChanges.summary).toEqual({ unchanged: 1, changed: 2, added: 1, removed: 0, majorVersionChanges: 1 });
    expect(evidence.packageChanges.changes).toEqual([
      { name: 'curl', arch: 'x86_64', from: '8.22.0-r0', to: '8.23.0-r0', change: 'changed', majorVersionChange: false },
      { name: 'libidn2', arch: 'x86_64', from: '', to: '2.3.7-r0', change: 'added', majorVersionChange: false },
      { name: 'zlib', arch: 'x86_64', from: '1.3.1-r2', to: '2.0.0-r0', change: 'changed', majorVersionChange: true },
    ]);
  });

  it('fails a candidate that lost its runtime configuration and cannot start (the 2026-11-02 Copa defect)', () => {
    const evidence = build({
      candidateImage: imageInspect(CANDIDATE_DIGEST, { Entrypoint: null, Cmd: null, ExposedPorts: null, StopSignal: '' }),
      candidateContainer: [{ State: { Status: 'not-started', Running: false, ExitCode: null } }],
    });

    expect(evidence.passed).toBe(false);
    expect(evidence.checks[0]).toMatchObject({
      id: 'image-config',
      status: 'fail',
      detail: 'Runtime configuration differs from the source: Cmd, Entrypoint, ExposedPorts, StopSignal.',
    });
    expect(evidence.checks[1]).toMatchObject({
      id: 'startup',
      status: 'fail',
      detail: 'Startup differs: source running, candidate could not be started.',
    });
  });

  it('ignores docker inspect keys that are not part of the runtime contract', () => {
    const evidence = build({ candidateImage: imageInspect(CANDIDATE_DIGEST, { Image: 'sha256:other', Hostname: 'x' }) });
    expect(evidence.checks[0].status).toBe('pass');
  });

  it('fails when a package is removed', () => {
    const evidence = build({ candidateTrivy: trivyReport([['musl', '1.2.5-r10'], ['curl', '8.23.0-r0']]) });
    expect(evidence.passed).toBe(false);
    expect(evidence.checks[3]).toMatchObject({ id: 'package-inventory', status: 'fail' });
    expect(evidence.checks[3].detail).toContain('A security patch must not remove packages.');
  });

  it('binds each pulled image to the requested digest', () => {
    expect(() => build({ candidateImage: imageInspect(SOURCE_DIGEST) })).toThrow(
      `The pulled candidate image is not bound to ${REPOSITORY}@${CANDIDATE_DIGEST}.`,
    );
  });

  it('rejects tags, a reused digest, other platforms and non RM-EXEC jobs', () => {
    expect(() => build({ candidateReference: `${REPOSITORY}:latest` })).toThrow(CandidateTestError);
    expect(() => build({ candidateReference: SOURCE_REF, candidateImage: imageInspect(SOURCE_DIGEST) })).toThrow(/must differ/);
    const arm = imageInspect(CANDIDATE_DIGEST);
    arm[0].Architecture = 'arm64';
    expect(() => build({ candidateImage: arm })).toThrow(/same platform/);
    expect(() => build({ jobId: 'RM-DRY-0001' })).toThrow(/RM-EXEC/);
  });

  it('parses registry references with ports and nested repositories', () => {
    expect(parseImmutableReference(`registry.local:5000/team/app/web@${SOURCE_DIGEST}`, 'ref')).toEqual({
      reference: `registry.local:5000/team/app/web@${SOURCE_DIGEST}`,
      repository: 'registry.local:5000/team/app/web',
      digest: SOURCE_DIGEST,
    });
  });
});

describe('image facts', () => {
  it('reports layers, size and the runtime configuration of both images, Env as names only', () => {
    const { imageFacts } = build({
      candidateImage: imageInspect(CANDIDATE_DIGEST, {}, { layers: [...BASE_LAYERS, PATCH_LAYER], size: 49_500_000 }),
    });
    expect(imageFacts.source).toEqual({
      sizeBytes: 48_000_000,
      diffIds: BASE_LAYERS,
      config: {
        Cmd: ['nginx', '-g', 'daemon off;'],
        Entrypoint: ['/docker-entrypoint.sh'],
        Env: ['PATH', 'NGINX_VERSION'],
        ExposedPorts: { '80/tcp': {} },
        StopSignal: 'SIGQUIT',
      },
    });
    expect(imageFacts.candidate).toMatchObject({ sizeBytes: 49_500_000, diffIds: [...BASE_LAYERS, PATCH_LAYER] });
    expect(JSON.stringify(imageFacts)).not.toContain('/usr/sbin');
    expect(JSON.stringify(imageFacts)).not.toContain('1.31.0');
  });

  it('never fails the test for a missing layer list or size, but refuses an absurd layer count', () => {
    const { imageFacts, passed } = build({ sourceImage: imageInspect(SOURCE_DIGEST, {}, { layers: null, size: null }) });
    expect(passed).toBe(true);
    expect(imageFacts.source).toMatchObject({ sizeBytes: null, diffIds: [] });
    const many = Array.from({ length: 513 }, (_, index) => `sha256:${String(index).padStart(64, '0')}`);
    expect(() => build({ candidateImage: imageInspect(CANDIDATE_DIGEST, {}, { layers: many }) })).toThrow(CandidateTestError);
  });

  it('keeps a variable name without a value and drops empty entries', () => {
    expect(envNameOf('SECRET_TOKEN=abc=def')).toBe('SECRET_TOKEN');
    expect(envNameOf('FLAG')).toBe('FLAG');
    expect(envNameOf('')).toBe('');
  });
});

describe('startup and health comparison', () => {
  const running = startupObservationOf(containerInspect({}));

  it('accepts run-to-completion images that exit with the same code', () => {
    const exited = startupObservationOf(containerInspect({ Status: 'exited', ExitCode: 0 }));
    expect(startupCheck(exited, exited).status).toBe('pass');
    const crashed = startupObservationOf(containerInspect({ Status: 'exited', ExitCode: 3 }));
    expect(startupCheck(running, crashed)).toMatchObject({ status: 'fail', detail: 'Startup differs: source running, candidate exited with code 3.' });
  });

  it('fails an OOM-killed candidate', () => {
    const oom = startupObservationOf(containerInspect({ Status: 'exited', ExitCode: 137, OOMKilled: true }));
    expect(startupCheck(startupObservationOf(containerInspect({ Status: 'exited', ExitCode: 137 })), oom).status).toBe('fail');
  });

  it('accepts two images that have no default command at all', () => {
    const notStarted = startupObservationOf([{ State: { Status: 'not-started', ExitCode: null } }]);
    expect(startupCheck(notStarted, notStarted).detail).toBe('Neither image starts on its own (no default command); behaviour is unchanged.');
  });

  it('compares health only when a HEALTHCHECK exists and the result settled', () => {
    const healthy = startupObservationOf(containerInspect({ Health: { Status: 'healthy' } }));
    const starting = startupObservationOf(containerInspect({ Health: { Status: 'starting' } }));
    const defined = { sourceDefinesHealthcheck: true, candidateDefinesHealthcheck: true };
    expect(healthcheckCheck(defined, healthy, healthy).status).toBe('pass');
    expect(healthcheckCheck(defined, healthy, starting).status).toBe('fail');
    expect(healthcheckCheck({ sourceDefinesHealthcheck: false, candidateDefinesHealthcheck: false }, running, running).status).toBe(
      'not-applicable',
    );
  });
});

describe('package inventory', () => {
  it('builds epoch, version and release into one version string and keeps architectures apart', () => {
    const inventory = packageInventoryOf(
      trivyReport([
        ['openssl', '3.0.15', { Epoch: 1, Release: '1.el9' }],
        ['libc6', '2.36-9', { Arch: 'amd64' }],
        ['libc6', '2.36-9', { Arch: 'i386' }],
      ]),
    );
    expect([...inventory.packages.values()]).toEqual([
      { name: 'openssl', arch: 'x86_64', version: '1:3.0.15-1.el9' },
      { name: 'libc6', arch: 'amd64', version: '2.36-9' },
      { name: 'libc6', arch: 'i386', version: '2.36-9' },
    ]);
    expect(inventory.os).toBe('alpine 3.22.1');
  });

  it('flags an epoch change as a major version change', () => {
    const diff = diffPackages(
      packageInventoryOf(trivyReport([['bash', '5.2.15', { Epoch: 0 }]])),
      packageInventoryOf(trivyReport([['bash', '5.2.15', { Epoch: 1 }]])),
    );
    expect(diff.changes[0]).toMatchObject({ from: '5.2.15', to: '1:5.2.15', majorVersionChange: true });
  });

  it('requires a SchemaVersion 2 report with detected OS packages', () => {
    expect(() => packageInventoryOf({ SchemaVersion: 1 })).toThrow(/SchemaVersion 2/);
    expect(() => packageInventoryOf({ SchemaVersion: 2, Results: [{ Class: 'lang-pkgs' }] })).toThrow(/no OS packages/);
  });
});
