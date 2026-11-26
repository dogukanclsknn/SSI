import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { deliver } from '../../scripts/canonical-report.mjs';
import { EVIDENCE_PURPOSE, verifyWorkerEvidenceRequest } from './workerEvidenceAuth.js';

const pipelineFile = new URL('../../azure-pipelines-canonical-trivy-scan.yml', import.meta.url);
const SECRET = 'canonical-report-secret-with-at-least-32-bytes';
const JOB_ID = 'RM-DRY-0007';
// The published artifact is compact JSON; the bytes must reach SSI unchanged.
const REPORT_BYTES =
  '{"SchemaVersion":2,"ArtifactName":"x@sha256:aa","Results":[{"Class":"os-pkgs"}]}';

describe('canonical scan pipeline definition', () => {
  const pipeline = () => readFileSync(pipelineFile, 'utf8');

  it('stays manual and delivers only when asked, after the artifact is published', () => {
    const text = pipeline();
    expect(text).toMatch(/^trigger: none$/m);
    expect(text).toMatch(/^pr: none$/m);
    expect(text).toMatch(
      /- name: deliverToSsi\n\s+displayName: [^\n]+\n\s+type: boolean\n\s+default: false/,
    );
    expect(text).toMatch(
      /- name: remediationJobId\n\s+displayName: [^\n]+\n\s+type: string\n\s+default: ''/,
    );
    expect(text.indexOf("displayName: 'Publish canonical Trivy JSON'")).toBeLessThan(
      text.indexOf("displayName: 'Deliver canonical report to SSI'"),
    );
    expect(text.indexOf("displayName: 'Deliver canonical report to SSI'")).toBeLessThan(
      text.indexOf("displayName: 'Remove temporary scanner credentials and cache'"),
    );
    expect(text).toContain('- checkout: self');
    // Azure DevOps renders boolean parameters as True/False: normalised before the check.
    expect(text).toContain(
      `DELIVER_TO_SSI="$(printf '%s' "\${SSI_CANONICAL_DELIVER:-}" | tr '[:upper:]' '[:lower:]')"`,
    );
    expect(text).toContain('SSI_CANONICAL_DELIVER: ${{ parameters.deliverToSsi }}');
  });

  it('keeps the secret out of the log and falls back to the artifact when SSI is not configured', () => {
    const text = pipeline();
    expect(text).toContain('SSI_CANONICAL_REPORT_HMAC_SECRET: $(SSI_CANONICAL_REPORT_HMAC_SECRET)');
    expect(text).not.toMatch(/echo[^\n]*\$\{?SSI_CANONICAL_REPORT_HMAC_SECRET/);
    expect(text).toContain('task.complete result=SucceededWithIssues');
    expect(text).toContain("fail 'SSI rejected the canonical report");
  });
});

describe('canonical report delivery', () => {
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

  function reportFile(content = REPORT_BYTES) {
    directory = mkdtempSync(join(tmpdir(), 'ssi-canonical-'));
    const file = join(directory, 'canonical-trivy.json');
    writeFileSync(file, content);
    return file;
  }

  const options = (base, extra = {}) => ({
    file: reportFile(),
    'job-id': JOB_ID,
    'api-base-url': base,
    'allow-http': 'true',
    'worker-id': 'LinuxAgent2:build-agent-01',
    ...extra,
  });

  it('signs the exact published bytes for the Dry Run and posts them to its worker route', async () => {
    let received;
    const base = await startServer((request, response) => {
      const chunks = [];
      request.on('data', (chunk) => chunks.push(chunk));
      request.on('end', () => {
        received = {
          url: request.url,
          headers: request.headers,
          body: Buffer.concat(chunks).toString('utf8'),
        };
        response.writeHead(200, { 'Content-Type': 'application/json' });
        response.end('{}');
      });
    });
    const result = await deliver(options(base), {
      env: { SSI_CANONICAL_REPORT_HMAC_SECRET: SECRET },
    });
    expect(result).toMatchObject({ delivered: true, status: 200, attempts: 1 });
    expect(received.url).toBe(`/api/v1/remediation/${JOB_ID}/worker-canonical-report`);
    expect(received.body).toBe(REPORT_BYTES);
    const verified = verifyWorkerEvidenceRequest({
      jobId: JOB_ID,
      rawBody: received.body,
      headers: received.headers,
      secret: SECRET,
      purpose: EVIDENCE_PURPOSE.CANONICAL_REPORT,
    });
    expect(verified.workerId).toBe('LinuxAgent2:build-agent-01');
    // Domain separation: the signature is worthless as remediation evidence.
    expect(() =>
      verifyWorkerEvidenceRequest({
        jobId: JOB_ID,
        rawBody: received.body,
        headers: received.headers,
        secret: SECRET,
        purpose: EVIDENCE_PURPOSE.REMEDIATION,
      }),
    ).toThrow();
  });

  it('reports SSI as unreachable after retries and never retries a rejection', async () => {
    let calls = 0;
    const base = await startServer((request, response) => {
      calls += 1;
      request.resume();
      request.on('end', () => {
        response.writeHead(calls <= 3 ? 503 : 422, { 'Content-Type': 'application/json' });
        response.end(
          JSON.stringify({ message: calls <= 3 ? 'down' : 'source digest does not match' }),
        );
      });
    });
    const env = { SSI_CANONICAL_REPORT_HMAC_SECRET: SECRET };
    const sleep = async () => {};
    expect(await deliver(options(base), { env, sleep })).toMatchObject({
      delivered: false,
      permanent: false,
      attempts: 3,
    });
    expect(await deliver(options(base), { env, sleep })).toMatchObject({
      delivered: false,
      permanent: true,
      status: 422,
      attempts: 1,
    });
  });

  it('refuses to run without the secret, with a bad job ID or over plain HTTP', async () => {
    const base = 'http://127.0.0.1:9/api/v1';
    await expect(deliver(options(base), { env: {} })).rejects.toThrow(
      /SSI_CANONICAL_REPORT_HMAC_SECRET is required/,
    );
    await expect(
      deliver(options(base), { env: { SSI_CANONICAL_REPORT_HMAC_SECRET: '$(SECRET)' } }),
    ).rejects.toThrow(/is required/);
    const env = { SSI_CANONICAL_REPORT_HMAC_SECRET: SECRET };
    await expect(deliver(options(base, { 'job-id': '../admin' }), { env })).rejects.toThrow(
      /valid SSI job ID/,
    );
    await expect(deliver(options(base, { 'allow-http': 'false' }), { env })).rejects.toThrow(
      /must use HTTPS/,
    );
  });
});
