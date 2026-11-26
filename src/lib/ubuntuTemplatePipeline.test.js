import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { parameterValues, runBash, stepEnv, stepScript } from './pipelineSteps.testkit.js';

// azure-pipelines-os-template-ubuntu.yml: the SSI Ubuntu template worker.
const pipeline = readFileSync(
  new URL('../../azure-pipelines-os-template-ubuntu.yml', import.meta.url),
  'utf8',
);
const BUILD_STEP = 'Validate inputs and build the template';
const SHA = 'ab'.repeat(32);

describe('Ubuntu template pipeline definition', () => {
  it('is manual and runs on LinuxPool', () => {
    expect(pipeline).toMatch(/^trigger: none$/m);
    expect(pipeline).toMatch(/^pr: none$/m);
    expect(pipeline).toMatch(/^pool: 'LinuxPool'$/m);
  });

  it('hands parameters to bash only through the environment', () => {
    for (const step of [BUILD_STEP, 'Deliver the signed result to SSI']) {
      expect(stepScript(pipeline, step), step).not.toContain('${{');
    }
    expect(stepEnv(pipeline, BUILD_STEP)).toEqual({
      SSI_TEMPLATE_BASE_IMAGE_URL: '${{ parameters.baseImageUrl }}',
      SSI_TEMPLATE_BASE_IMAGE_SHA256: '${{ parameters.baseImageSha256 }}',
      SSI_TEMPLATE_NAME: '${{ parameters.templateName }}',
      SSI_TEMPLATE_DISK_SIZE_GB: '${{ parameters.diskSizeGb }}',
      SSI_TEMPLATE_APT_MIRROR: '${{ parameters.aptMirror }}',
      SSI_TEMPLATE_DELIVER: '${{ parameters.deliverToSsi }}',
      SSI_TEMPLATE_BUILD_REQUEST: '${{ parameters.osTemplateBuildId }}',
      SSI_API_BASE_URL: '${{ parameters.ssiApiBaseUrl }}',
      SSI_ALLOW_INSECURE_POC_API: '${{ parameters.allowInsecurePocApi }}',
      SSI_OS_TEMPLATE_EVIDENCE_HMAC_SECRET: '$(SSI_OS_TEMPLATE_EVIDENCE_HMAC_SECRET)',
      SSI_IMAGE_CACHE: '$(Agent.WorkFolder)/ssi-os-template-cache',
    });
  });

  it('can only call this SSI back, like the other workers', () => {
    expect(parameterValues(pipeline, 'ssiApiBaseUrl')).toEqual([
      'http://10.0.0.10:5021/api/v1',
      'http://ssi.example.com/api/v1',
    ]);
  });

  it('uses the pinned Trivy image of the canonical scan worker', () => {
    const digest = /ghcr\.io\/aquasecurity\/trivy@sha256:[0-9a-f]{64}/;
    const canonical = readFileSync(
      new URL('../../azure-pipelines-canonical-trivy-scan.yml', import.meta.url),
      'utf8',
    );
    expect(pipeline.match(digest)[0]).toBe(canonical.match(digest)[0]);
    const dockerfile = readFileSync(
      new URL('../../poc/os-template/linux/Dockerfile', import.meta.url),
      'utf8',
    );
    expect(dockerfile.match(digest)[0]).toBe(canonical.match(digest)[0]);
  });

  it('delivers only when asked and after a successful build', () => {
    expect(pipeline).toMatch(
      /displayName: 'Deliver the signed result to SSI'\n {12}condition: and\(succeeded\(\), eq\('\$\{\{ parameters\.deliverToSsi \}\}', 'true'\)\)/,
    );
    expect(pipeline).not.toMatch(/echo[^\n]*SSI_OS_TEMPLATE_EVIDENCE_HMAC_SECRET/);
  });

  it('publishes the evidence always, one artifact per format, and delivers to SSI last', () => {
    expect(pipeline).toContain("ArtifactName: 'os-template-ubuntu-evidence'");
    expect(pipeline).toMatch(
      /displayName: 'Publish template evidence'\n {12}condition: succeededOrFailed\(\)/,
    );
    const order = [
      "ArtifactName: 'os-template-ubuntu-qcow2'",
      "ArtifactName: 'os-template-ubuntu-ova'",
      "ArtifactName: 'os-template-ubuntu-vhdx'",
      "displayName: 'Deliver the signed result to SSI'",
    ].map((marker) => pipeline.indexOf(marker));
    expect(order.every((index) => index > 0)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
    // SSI checks that the location names the qcow2 artifact (src/lib/osTemplate.js).
    expect(stepScript(pipeline, 'Deliver the signed result to SSI')).toContain(
      '--location-path "os-template-ubuntu-qcow2/$(basename "${qcow2}")"',
    );
    expect(pipeline).not.toContain('os-template-ubuntu-images');
    const cleanup = stepScript(pipeline, 'Cleanup (only this run)');
    expect(cleanup).toContain('rm -rf "${PIPELINE_WORKSPACE}/os-template-ubuntu"');
    expect(cleanup).toContain('docker image rm "ssi-os-template-builder:${BUILD_BUILDID}"');
    expect(pipeline).toMatch(
      /displayName: 'Cleanup \(only this run\)'\n {12}condition: always\(\)/,
    );
  });
});

// The build step with a stand-in docker on PATH that records its arguments: the step's own
// checks and the container it would start, without Docker or a four-gigabyte image.
describe('Ubuntu template pipeline build step', () => {
  let directory;
  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'ssi-ubuntu-pipeline-'));
    mkdirSync(join(directory, 'bin'));
    mkdirSync(join(directory, 'staging'));
    const docker = join(directory, 'bin/docker');
    writeFileSync(
      docker,
      [
        '#!/usr/bin/env bash',
        'printf "%s\\n" "$*" >> "$DOCKER_LOG"',
        'if [[ "$1" == run && "$*" == *build-ubuntu-template.sh* ]]; then exit "${BUILDER_EXIT:-0}"; fi',
        'exit 0',
        '',
      ].join('\n'),
    );
    chmodSync(docker, 0o755);
  });
  afterEach(() => rmSync(directory, { recursive: true, force: true }));

  const run = (inputs = {}) => {
    const result = runBash(stepScript(pipeline, BUILD_STEP), {
      PATH: `${join(directory, 'bin')}:${process.env.PATH}`,
      DOCKER_LOG: join(directory, 'docker.log'),
      MIN_FREE_GB: '0',
      TRIVY_IMAGE: 'trivy@sha256:x',
      PIPELINE_WORKSPACE: join(directory, 'ws'),
      BUILD_ARTIFACTSTAGINGDIRECTORY: join(directory, 'staging'),
      BUILD_SOURCESDIRECTORY: join(directory, 'sources'),
      BUILD_BUILDID: '4242',
      SSI_IMAGE_CACHE: join(directory, 'cache'),
      SSI_TEMPLATE_BASE_IMAGE_URL:
        'https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-amd64.img',
      SSI_TEMPLATE_BASE_IMAGE_SHA256: SHA.toUpperCase(),
      SSI_TEMPLATE_NAME: 'ssi-ubuntu-2404',
      SSI_TEMPLATE_DISK_SIZE_GB: '20',
      SSI_TEMPLATE_APT_MIRROR: '',
      SSI_TEMPLATE_DELIVER: 'false',
      ...inputs,
    });
    const readOr = (path, fallback) => {
      try {
        return readFileSync(join(directory, path), 'utf8').trim();
      } catch {
        return fallback;
      }
    };
    const failure = readOr('staging/os-template-ubuntu/failure.txt', null);
    const log = readOr('docker.log', '');
    const docker = log ? log.split('\n') : [];
    return { ...result, failure, docker };
  };

  it.each([
    [{ SSI_TEMPLATE_BASE_IMAGE_SHA256: '' }, 'refuses an unpinned image'],
    [
      { SSI_TEMPLATE_BASE_IMAGE_URL: 'https://example.com/ubuntu.img' },
      'must be an official https://cloud-images.ubuntu.com',
    ],
    [
      { SSI_TEMPLATE_BASE_IMAGE_URL: 'https://cloud-images.ubuntu.com/../x/evil.img' },
      'must be an official',
    ],
    [{ SSI_TEMPLATE_NAME: 'Bad Name' }, 'templateName may hold'],
    [{ SSI_TEMPLATE_DISK_SIZE_GB: '4' }, 'diskSizeGb must be 10-200'],
    [{ SSI_TEMPLATE_APT_MIRROR: 'http://u:p@mirror/ubuntu' }, 'aptMirror must be an http(s) URL'],
  ])('refuses %o before Docker is touched', (change, message) => {
    const result = run(change);
    expect(result.status).toBe(1);
    expect(result.failure).toContain(message);
    expect(result.docker).toEqual([]);
  });

  it('neutralises an Azure DevOps logging command in a rejected value', () => {
    const result = run({ SSI_TEMPLATE_NAME: '##vso[task.setvariable variable=x]y' });
    expect(result.failure).toContain('##vso_[task.setvariable');
    expect(result.output).not.toMatch(/##vso\[task\.setvariable/);
  });

  it('checks the delivery to SSI before the build starts', () => {
    const deliver = {
      SSI_TEMPLATE_DELIVER: 'true',
      SSI_TEMPLATE_BUILD_REQUEST: 'OST-0002',
      SSI_API_BASE_URL: 'http://10.0.0.10:5021/api/v1',
    };
    expect(run({ ...deliver, SSI_TEMPLATE_BUILD_REQUEST: 'RM-1' }).failure).toContain(
      'osTemplateBuildId must look like OST-0001',
    );
    expect(run(deliver).failure).toContain('allowInsecurePocApi must be true');
    const unset = run({
      ...deliver,
      SSI_ALLOW_INSECURE_POC_API: 'true',
      SSI_OS_TEMPLATE_EVIDENCE_HMAC_SECRET: '$(SSI_OS_TEMPLATE_EVIDENCE_HMAC_SECRET)',
    });
    expect(unset.failure).toContain('SSI_OS_TEMPLATE_EVIDENCE_HMAC_SECRET is not set');
    expect(unset.docker).toEqual([]);
  });

  it('takes "none" as no mirror, since Azure DevOps refuses an empty parameter', () => {
    const result = run({ SSI_TEMPLATE_APT_MIRROR: 'none', SSI_TEMPLATE_BUILD_REQUEST: 'none' });
    expect(result.status).toBe(0);
    expect(result.docker.find((line) => line.includes('build-ubuntu-template.sh'))).toContain(
      'APT_MIRROR= ',
    );
    expect(pipeline).toMatch(/- name: aptMirror\n[^\n]*\n[^\n]*\n {4}default: none\n/);
    expect(pipeline).toMatch(/- name: osTemplateBuildId\n[^\n]*\n[^\n]*\n {4}default: none\n/);
  });

  it('builds in an unprivileged container with the pinned inputs', () => {
    const result = run();
    expect(result.status).toBe(0);
    expect(result.failure).toBeNull();
    const builder = result.docker.find((line) => line.includes('build-ubuntu-template.sh'));
    expect(builder).toContain('--user ');
    expect(builder).toContain(`BASE_IMAGE_SHA256=${SHA}`);
    expect(builder).toContain('BUILD_ID=ado-4242');
    expect(builder).toContain('/poc/os-template:/poc:ro');
    expect(builder).not.toMatch(/--privileged|docker\.sock|--cap-add/);
    expect(result.docker[0]).toMatch(/^build --pull -t ssi-os-template-builder:4242 /);
    expect(result.docker[1]).toContain('image --download-db-only');
  });

  it('reports a refused gate apart from a failed build', () => {
    expect(run({ BUILDER_EXIT: '1' }).failure).toContain('The gate refused the template');
    expect(run({ BUILDER_EXIT: '2' }).failure).toContain('The template build failed (exit 2)');
  });
});

describe('Ubuntu template pipeline staging per format', () => {
  let directory;
  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'ssi-ubuntu-stage-'));
    mkdirSync(join(directory, 'os-template-ubuntu/work/build/out'), { recursive: true });
  });
  afterEach(() => rmSync(directory, { recursive: true, force: true }));

  const stage = () =>
    runBash(stepScript(pipeline, 'Stage the template files per format'), {
      PIPELINE_WORKSPACE: directory,
    });
  const out = (name) => join(directory, 'os-template-ubuntu/work/build/out', name);

  it('moves each disk image into the folder of its own artifact', () => {
    for (const format of ['qcow2', 'ova', 'vhdx']) writeFileSync(out(`t-1.${format}`), format);
    writeFileSync(out('SHA256SUMS'), 'sums');
    expect(stage().ok).toBe(true);
    for (const format of ['qcow2', 'ova', 'vhdx']) {
      expect(
        readFileSync(join(directory, `os-template-ubuntu/publish/${format}/t-1.${format}`), 'utf8'),
      ).toBe(format);
    }
    expect(readFileSync(out('SHA256SUMS'), 'utf8')).toBe('sums');
  });

  it('stops when a format is missing', () => {
    writeFileSync(out('t-1.qcow2'), 'q');
    const result = stage();
    expect(result.ok).toBe(false);
    expect(result.output).toContain('Expected exactly one .ova file');
  });
});
