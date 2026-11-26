import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { deliver, renderSummary } from '../../scripts/image-inspection.mjs';
import { evidenceEndpoint } from '../../scripts/lib/signedEvidenceDelivery.mjs';
import { EVIDENCE_PURPOSE, verifyWorkerEvidenceRequest } from './workerEvidenceAuth.js';

const pipelineFile = new URL('../../azure-pipelines-image-inspection.yml', import.meta.url);
const SECRET = 'image-inspection-secret-with-at-least-32-bytes';
const DIGEST = `sha256:${'a'.repeat(64)}`;
const evidence = {
  contractVersion: 'ssi.image-inspection/v1',
  image: { immutableReference: `registry.example.com/ssi-images/onboarded/nginx@${DIGEST}`, digest: DIGEST },
  platform: 'linux/amd64',
  os: 'alpine 3.22.2',
  packages: [{ name: 'curl', arch: 'x86_64', version: '8.23.0-r0' }],
  facts: { sizeBytes: 62_997_887, diffIds: [`sha256:${'1'.repeat(64)}`], config: { Env: ['PATH', '<b>NGINX</b>|X'] } },
};

describe('image inspection pipeline definition', () => {
  const pipeline = () => readFileSync(pipelineFile, 'utf8');

  it('is manual, digest-only and validates its input before any registry call', () => {
    const text = pipeline();
    expect(text).toMatch(/^trigger: none$/m);
    expect(text).toMatch(/^pr: none$/m);
    expect(text).toContain('@sha256:[a-f0-9]{64}$ ]]');
    expect(text.indexOf('Input validation')).toBeLessThan(text.indexOf('docker login'));
    expect(text).toContain('--password-stdin');
    expect(text).toContain("shown() { printf '%s' \"$1\" | head -c 200 | sed 's/##vso\\[/##vso_[/g'; }");
    expect(text).toContain('printf \'%s\\n\' "$1" > "${EVIDENCE_DIR}/failure.txt"');
    expect(text).not.toMatch(/echo[^\n]*\$\{?HARBOR_ROBOT_SECRET/);
    expect(text).not.toMatch(/echo[^\n]*\$\{?SSI_IMAGE_INSPECTION_EVIDENCE_HMAC_SECRET/);
  });

  it('never starts a container from the inspected image', () => {
    const text = pipeline();
    // Every non-comment `docker run` line: only the Trivy package lister may run.
    const runs = text
      .split('\n')
      .filter((line) => !line.trim().startsWith('#') && /docker run\b/.test(line))
      .map((line) => line.trim());
    expect(runs).toEqual(['docker run --rm \\']);
    const runBlock = text.slice(text.indexOf('docker run --rm'), text.indexOf('"${IMAGE_REFERENCE}"\n', text.indexOf('docker run --rm')));
    expect(runBlock).toContain('"${TRIVY_IMAGE}" image');
    expect(runBlock).toContain('--image-src remote');
    expect(text).not.toContain('--privileged');
    expect(text).not.toContain('docker.sock');
    expect(text).not.toContain('docker exec');
  });

  it('lists packages without the vulnerability database and removes what it pulled', () => {
    const text = pipeline();
    expect(text).toContain('--scanners license');
    expect(text).toContain('--pkg-types os');
    expect(text).toContain('trap cleanup EXIT');
    expect(text).toContain('docker rmi "${IMAGE_REFERENCE}"');
    expect(text).toMatch(/displayName: 'Cleanup \(only this run\)'\n\s+condition: always\(\)/);
  });

  it('never ends green when the result did not reach SSI', () => {
    const text = pipeline();
    expect(text).toContain('##vso[task.complete result=SucceededWithIssues;]');
    expect(text).toContain('SSI_IMAGE_INSPECTION_EVIDENCE_HMAC_SECRET: $(SSI_IMAGE_INSPECTION_EVIDENCE_HMAC_SECRET)');
  });
});

describe('image inspection summary', () => {
  it('summarises the image without passing HTML or table breaks through', () => {
    const markdown = renderSummary(evidence);
    expect(markdown).toContain('- OS packages: 1');
    expect(markdown).toContain('- Layers: 1 · Size: 63.0 MB');
    expect(markdown).toContain('names only): PATH, bNGINX/b X');
  });
});

describe('image inspection delivery', () => {
  let server;
  let directory;

  afterEach(async () => {
    if (server) await new Promise((resolve) => server.close(resolve));
    if (directory) rmSync(directory, { recursive: true, force: true });
    server = undefined;
    directory = undefined;
  });

  async function startServer(handler) {
    server = createServer(handler);
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    return `http://127.0.0.1:${server.address().port}/api/v1`;
  }

  function evidenceFile(content = evidence) {
    directory = mkdtempSync(join(tmpdir(), 'ssi-inspection-'));
    const file = join(directory, 'image-inspection-result.json');
    writeFileSync(file, JSON.stringify(content));
    return file;
  }

  it('signs the exact body for the image digest and posts it to the worker route', async () => {
    let received;
    const base = await startServer((request, response) => {
      const chunks = [];
      request.on('data', (chunk) => chunks.push(chunk));
      request.on('end', () => {
        received = { url: request.url, headers: request.headers, body: Buffer.concat(chunks).toString('utf8') };
        response.writeHead(200, { 'Content-Type': 'application/json' });
        response.end('{}');
      });
    });
    const result = await deliver(
      { file: evidenceFile(), 'api-base-url': base, 'allow-http': 'true', 'worker-id': 'LinuxAgent1:build-agent-01' },
      { env: { SSI_IMAGE_INSPECTION_EVIDENCE_HMAC_SECRET: SECRET } },
    );
    expect(result).toMatchObject({ delivered: true, status: 200, attempts: 1 });
    expect(received.url).toBe(`/api/v1/image-inspections/${encodeURIComponent(DIGEST)}/worker`);
    const verified = verifyWorkerEvidenceRequest({
      jobId: DIGEST,
      rawBody: received.body,
      headers: received.headers,
      secret: SECRET,
      purpose: EVIDENCE_PURPOSE.IMAGE_INSPECTION,
    });
    expect(verified.workerId).toBe('LinuxAgent1:build-agent-01');
    // Domain separation: the same signature is worthless for another worker purpose.
    expect(() =>
      verifyWorkerEvidenceRequest({
        jobId: DIGEST,
        rawBody: received.body,
        headers: received.headers,
        secret: SECRET,
        purpose: EVIDENCE_PURPOSE.CANDIDATE_TEST,
      }),
    ).toThrow();
  });

  it('retries transient failures, reports SSI as unreachable, and never retries a rejection', async () => {
    let calls = 0;
    const base = await startServer((request, response) => {
      calls += 1;
      request.resume();
      request.on('end', () => {
        response.writeHead(calls <= 3 ? 503 : 422, { 'Content-Type': 'application/json' });
        response.end(JSON.stringify({ message: calls <= 3 ? 'down' : 'Env must list names only' }));
      });
    });
    const options = { file: evidenceFile(), 'api-base-url': base, 'allow-http': 'true', 'worker-id': 'agent' };
    const env = { SSI_IMAGE_INSPECTION_EVIDENCE_HMAC_SECRET: SECRET };
    const sleep = async () => {};
    expect(await deliver(options, { env, sleep })).toMatchObject({ delivered: false, permanent: false, attempts: 3 });
    expect(await deliver(options, { env, sleep })).toMatchObject({ delivered: false, permanent: true, status: 422, attempts: 1 });
  });

  it('refuses unsafe configurations before sending anything', async () => {
    const options = { file: evidenceFile(), 'api-base-url': 'http://ssi.internal/api/v1', 'worker-id': 'agent' };
    await expect(deliver(options, { env: {} })).rejects.toThrow(/Secret SSI_IMAGE_INSPECTION_EVIDENCE_HMAC_SECRET is required/);
    await expect(deliver(options, { env: { SSI_IMAGE_INSPECTION_EVIDENCE_HMAC_SECRET: '$(SECRET)' } })).rejects.toThrow(/is required/);
    await expect(deliver(options, { env: { SSI_IMAGE_INSPECTION_EVIDENCE_HMAC_SECRET: SECRET } })).rejects.toThrow(/must use HTTPS/);
    expect(() => evidenceEndpoint('https://user:pass@ssi.internal/api/v1', 'x')).toThrow(/credentials/);
    const noDigest = { ...options, file: evidenceFile({ ...evidence, image: {} }), 'allow-http': 'true' };
    await expect(deliver(noDigest, { env: { SSI_IMAGE_INSPECTION_EVIDENCE_HMAC_SECRET: SECRET } })).rejects.toThrow(/does not name an image digest/);
  });
});
