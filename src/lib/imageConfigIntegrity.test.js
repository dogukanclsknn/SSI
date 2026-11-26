import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import {
  changedRuntimeFields,
  configDigestOf,
  ImageConfigIntegrityError,
  manifestMediaTypeOf,
  planConfigRestore,
  platformOf,
  restoredImageManifest,
  runtimeConfigOf,
  selectImageManifest,
} from './imageConfigIntegrity.js';

const digest = (char) => `sha256:${char.repeat(64)}`;
const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

// nginx:alpine-like source runtime configuration.
function sourceConfig() {
  return {
    architecture: 'amd64',
    os: 'linux',
    config: {
      Env: ['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'NGINX_VERSION=1.27.5'],
      Entrypoint: ['/docker-entrypoint.sh'],
      Cmd: ['nginx', '-g', 'daemon off;'],
      ExposedPorts: { '80/tcp': {} },
      Labels: { maintainer: 'NGINX Docker Maintainers' },
      StopSignal: 'SIGQUIT',
    },
    rootfs: { type: 'layers', diff_ids: [digest('1')] },
    history: [{ created_by: 'source' }],
  };
}

// What the Copa frontend produced: patched layers, BuildKit default runtime config.
function strippedOutputConfig() {
  return {
    architecture: 'amd64',
    os: 'linux',
    config: {
      Env: ['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'],
      WorkingDir: '/',
    },
    rootfs: { type: 'layers', diff_ids: [digest('1'), digest('2')] },
    history: [{ created_by: 'source' }, { created_by: 'copa' }],
  };
}

function imageManifest(configDigest = digest('c')) {
  return {
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.manifest.v1+json',
    config: { mediaType: 'application/vnd.oci.image.config.v1+json', digest: configDigest, size: 100 },
    layers: [
      { mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip', digest: digest('a'), size: 10 },
      { mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip', digest: digest('b'), size: 20 },
    ],
  };
}

function index(manifests) {
  return { schemaVersion: 2, mediaType: 'application/vnd.oci.image.index.v1+json', manifests };
}

const attestation = {
  mediaType: 'application/vnd.oci.image.manifest.v1+json',
  digest: digest('e'),
  size: 800,
  annotations: { 'vnd.docker.reference.type': 'attestation-manifest', 'vnd.docker.reference.digest': digest('d') },
  platform: { architecture: 'unknown', os: 'unknown' },
};
const amd64 = { mediaType: 'application/vnd.oci.image.manifest.v1+json', digest: digest('d'), size: 600, platform: { os: 'linux', architecture: 'amd64' } };
const arm64 = { mediaType: 'application/vnd.oci.image.manifest.v1+json', digest: digest('f'), size: 600, platform: { os: 'linux', architecture: 'arm64', variant: 'v8' } };

describe('image configuration comparison', () => {
  it('reports every runtime field the Copa output lost or changed', () => {
    expect(changedRuntimeFields(sourceConfig(), strippedOutputConfig())).toEqual([
      'Cmd',
      'Entrypoint',
      'Env',
      'ExposedPorts',
      'Labels',
      'StopSignal',
      'WorkingDir',
    ]);
  });

  it('treats absent, null and empty fields as the same configuration and ignores key order', () => {
    const source = sourceConfig();
    const output = sourceConfig();
    output.config = {
      StopSignal: 'SIGQUIT',
      Labels: { maintainer: 'NGINX Docker Maintainers' },
      ExposedPorts: { '80/tcp': {} },
      Cmd: ['nginx', '-g', 'daemon off;'],
      Entrypoint: ['/docker-entrypoint.sh'],
      Env: [...source.config.Env],
      Volumes: null,
      OnBuild: [],
      WorkingDir: '',
      ArgsEscaped: false,
    };
    expect(changedRuntimeFields(source, output)).toEqual([]);
  });

  it('keeps Env and Cmd order significant', () => {
    const output = sourceConfig();
    output.config.Cmd = ['-g', 'daemon off;', 'nginx'];
    output.config.Env = [...output.config.Env].reverse();
    expect(changedRuntimeFields(sourceConfig(), output)).toEqual(['Cmd', 'Env']);
  });

  it('rejects a config that is not an object', () => {
    expect(() => runtimeConfigOf(null)).toThrow(ImageConfigIntegrityError);
    expect(() => runtimeConfigOf({ config: [] })).toThrow(/runtime "config" section/);
  });

  it('derives the platform including the variant', () => {
    expect(platformOf(sourceConfig())).toBe('linux/amd64');
    expect(platformOf({ os: 'linux', architecture: 'arm64', variant: 'v8' })).toBe('linux/arm64/v8');
    expect(() => platformOf({ os: 'linux' })).toThrow(/os and architecture/);
  });
});

describe('restore planning', () => {
  it('keeps a Copa output whose runtime configuration already matches', () => {
    const output = { ...strippedOutputConfig(), config: sourceConfig().config };
    expect(planConfigRestore({ sourceConfig: sourceConfig(), outputConfig: output })).toEqual({
      status: 'preserved',
      platform: 'linux/amd64',
      changedFields: [],
      restoredConfig: null,
    });
  });

  it('restores only the runtime section and keeps the patched rootfs and history', () => {
    const plan = planConfigRestore({ sourceConfig: sourceConfig(), outputConfig: strippedOutputConfig() });

    expect(plan.status).toBe('restore-required');
    expect(plan.restoredConfig.config).toEqual(sourceConfig().config);
    expect(plan.restoredConfig.rootfs).toEqual(strippedOutputConfig().rootfs);
    expect(plan.restoredConfig.history).toEqual(strippedOutputConfig().history);
    expect(changedRuntimeFields(sourceConfig(), plan.restoredConfig)).toEqual([]);
  });

  it('refuses to compare different platforms', () => {
    const output = { ...strippedOutputConfig(), architecture: 'arm64' };
    expect(() => planConfigRestore({ sourceConfig: sourceConfig(), outputConfig: output })).toThrow(
      /does not match the source platform/,
    );
  });

  it('points the restored manifest at the new config and keeps every layer', () => {
    const manifest = restoredImageManifest(imageManifest(), { digest: digest('9'), size: 321 });
    expect(manifest.config).toEqual({ mediaType: 'application/vnd.oci.image.config.v1+json', digest: digest('9'), size: 321 });
    expect(manifest.layers).toEqual(imageManifest().layers);
    expect(() => restoredImageManifest(index([amd64]), { digest: digest('9'), size: 1 })).toThrow(/not an index/);
  });

  it('pushes the restored manifest with the patched manifest media type', () => {
    expect(manifestMediaTypeOf(imageManifest())).toBe('application/vnd.oci.image.manifest.v1+json');
    const docker = { ...imageManifest(), mediaType: undefined };
    docker.config = { ...docker.config, mediaType: 'application/vnd.docker.container.image.v1+json' };
    expect(manifestMediaTypeOf(docker)).toBe('application/vnd.docker.distribution.manifest.v2+json');
  });
});

describe('image manifest selection', () => {
  it('returns null for an image manifest and skips attestation manifests in an index', () => {
    expect(selectImageManifest(imageManifest())).toBeNull();
    expect(selectImageManifest(index([amd64, attestation]))).toBe(digest('d'));
  });

  it('selects the source image for the patched platform from a multi-platform index', () => {
    expect(selectImageManifest(index([amd64, arm64, attestation]), 'linux/arm64/v8')).toBe(digest('f'));
    expect(() => selectImageManifest(index([arm64]), 'linux/amd64')).toThrow(/exactly one linux\/amd64/);
  });

  it('fails closed on a multi-platform remediation output', () => {
    expect(() => selectImageManifest(index([amd64, arm64]))).toThrow(/Multi-platform outputs are not supported/);
  });

  it('requires a schemaVersion 2 manifest with a sha256 config digest', () => {
    expect(() => selectImageManifest({ schemaVersion: 1 })).toThrow(/schemaVersion 2/);
    expect(configDigestOf(imageManifest())).toBe(digest('c'));
    expect(() => configDigestOf(imageManifest('sha256:short'))).toThrow(/sha256/);
  });
});

describe('scripts/image-config-integrity.mjs', () => {
  const tool = fileURLToPath(new URL('../../scripts/image-config-integrity.mjs', import.meta.url));
  let directory;

  afterEach(() => {
    if (directory) rmSync(directory, { recursive: true, force: true });
    directory = undefined;
  });

  function workspace() {
    directory = mkdtempSync(join(tmpdir(), 'ssi-config-integrity-'));
    return directory;
  }

  function writeJsonFile(name, value) {
    const path = join(directory, name);
    writeFileSync(path, JSON.stringify(value));
    return path;
  }

  function run(...args) {
    return execFileSync(process.execPath, [tool, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  }

  function runFailure(...args) {
    try {
      run(...args);
    } catch (error) {
      return { status: error.status, stderr: String(error.stderr) };
    }
    throw new Error('expected the tool to fail');
  }

  it('plans a restore, then verifies the restored image and writes the evidence', () => {
    workspace();
    const source = writeJsonFile('source-config.json', sourceConfig());
    const copaConfig = writeJsonFile('copa-output-config.json', strippedOutputConfig());
    const copaManifest = writeJsonFile('copa-output-manifest.json', imageManifest(sha256(readFileSync(copaConfig))));

    expect(run('plan', '--source-config', source, '--output-config', copaConfig, '--output-manifest', copaManifest, '--out-dir', directory)).toBe(
      'restore-required',
    );
    const plan = JSON.parse(readFileSync(join(directory, 'plan.json'), 'utf8'));
    const restoredConfigBytes = readFileSync(join(directory, 'restored-config.json'));
    const restoredManifestBytes = readFileSync(join(directory, 'restored-manifest.json'));
    expect(plan).toMatchObject({
      status: 'restore-required',
      platform: 'linux/amd64',
      changedFields: ['Cmd', 'Entrypoint', 'Env', 'ExposedPorts', 'Labels', 'StopSignal', 'WorkingDir'],
      restoredConfigDigest: sha256(restoredConfigBytes),
      restoredManifestDigest: sha256(restoredManifestBytes),
      restoredManifestMediaType: 'application/vnd.oci.image.manifest.v1+json',
    });
    expect(JSON.parse(restoredManifestBytes).config.digest).toBe(plan.restoredConfigDigest);
    expect(run('field', '--file', join(directory, 'plan.json'), '--name', 'changedFields')).toBe(
      'Cmd, Entrypoint, Env, ExposedPorts, Labels, StopSignal, WorkingDir',
    );

    const evidencePath = join(directory, 'config-integrity.json');
    expect(
      run(
        'verify',
        '--plan', join(directory, 'plan.json'),
        '--source-config', source,
        '--output-config', join(directory, 'restored-config.json'),
        '--output-manifest', join(directory, 'restored-manifest.json'),
        '--copa-output-digest', digest('0'),
        '--output-digest', plan.restoredManifestDigest,
        '--out', evidencePath,
      ),
    ).toBe('restored');
    expect(JSON.parse(readFileSync(evidencePath, 'utf8'))).toEqual({
      contractVersion: 'ssi.image-config-integrity/v1',
      status: 'restored',
      verified: true,
      platform: 'linux/amd64',
      restoredFields: plan.changedFields,
      layersPreserved: true,
      sourceConfigDigest: sha256(readFileSync(source)),
      copaOutputDigest: digest('0'),
      copaConfigDigest: sha256(readFileSync(copaConfig)),
      outputDigest: plan.restoredManifestDigest,
      outputConfigDigest: plan.restoredConfigDigest,
      runtimeConfigDigest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
    });
  });

  it('fails closed when the final image still differs or its layers changed', () => {
    workspace();
    const source = writeJsonFile('source-config.json', sourceConfig());
    const copaConfig = writeJsonFile('copa-output-config.json', strippedOutputConfig());
    const copaManifest = writeJsonFile('copa-output-manifest.json', imageManifest(sha256(readFileSync(copaConfig))));
    run('plan', '--source-config', source, '--output-config', copaConfig, '--output-manifest', copaManifest, '--out-dir', directory);
    const plan = JSON.parse(readFileSync(join(directory, 'plan.json'), 'utf8'));
    const verify = (outputConfig, outputManifest) =>
      runFailure(
        'verify',
        '--plan', join(directory, 'plan.json'),
        '--source-config', source,
        '--output-config', outputConfig,
        '--output-manifest', outputManifest,
        '--copa-output-digest', digest('0'),
        '--output-digest', plan.restoredManifestDigest,
        '--out', join(directory, 'config-integrity.json'),
      );

    const stillStripped = verify(copaConfig, join(directory, 'restored-manifest.json'));
    expect(stillStripped.status).toBe(1);
    expect(stillStripped.stderr).toContain('still differs from the source runtime configuration: Cmd, Entrypoint');

    const tampered = JSON.parse(readFileSync(join(directory, 'restored-manifest.json'), 'utf8'));
    tampered.layers[1].digest = digest('7');
    const layersChanged = verify(join(directory, 'restored-config.json'), writeJsonFile('tampered-manifest.json', tampered));
    expect(layersChanged.stderr).toContain('layers differ from the Copa output layers');
  });

  it('rejects downloaded bytes that do not match their digest', () => {
    workspace();
    const file = writeJsonFile('manifest.json', imageManifest());
    expect(() => run('verify-digest', '--file', file, '--digest', sha256(readFileSync(file)))).not.toThrow();
    expect(runFailure('verify-digest', '--file', file, '--digest', digest('0')).stderr).toContain('does not match the expected');
  });

  it('prints the digest of a manifest that is already the platform image', () => {
    workspace();
    const file = writeJsonFile('manifest.json', imageManifest());
    expect(run('select-image-manifest', '--manifest', file, '--platform', '')).toBe(sha256(readFileSync(file)));
    expect(runFailure('unknown-command').stderr).toContain('Unknown command');
  });
});
