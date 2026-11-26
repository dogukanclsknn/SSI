import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { deliver, renderSummary } from '../../scripts/candidate-test.mjs';
import { EVIDENCE_PURPOSE, verifyWorkerEvidenceRequest } from './workerEvidenceAuth.js';

const pipelineFile = new URL('../../azure-pipelines-candidate-test.yml', import.meta.url);
const SECRET = 'candidate-test-secret-with-at-least-32-bytes';
const evidence = {
  contractVersion: 'ssi.candidate-test/v1',
  remediationJobId: 'RM-EXEC-0004',
  platform: 'linux/amd64',
  source: { immutableReference: 'harbor/p/r@sha256:aa' },
  candidate: { immutableReference: 'harbor/p/r@sha256:bb' },
  checks: [{ id: 'startup', status: 'pass', detail: 'Starts | like <b>the</b> source' }],
  packageChanges: { changes: [{ name: 'zlib', change: 'changed', from: '1.3', to: '2.0', majorVersionChange: true }] },
  passed: true,
};

describe('candidate test pipeline definition', () => {
  const pipeline = () => readFileSync(pipelineFile, 'utf8');

  it('is manual, digest-only and validates every parameter before any registry call', () => {
    const text = pipeline();
    expect(text).toMatch(/^trigger: none$/m);
    expect(text).toMatch(/^pr: none$/m);
    expect(text).toContain("=~ ^RM-EXEC-[0-9]{4,}$ ]] || fail 'remediationJobId must identify a verified RM-EXEC job.'");
    expect(text).toContain('@sha256:[a-f0-9]{64}$ ]]');
    expect(text.indexOf('Input validation')).toBeLessThan(text.indexOf('docker login'));
    expect(text).toContain('--password-stdin');
    // Never print a secret's value (its name in a warning is fine).
    expect(text).not.toMatch(/echo[^\n]*\$\{?HARBOR_ROBOT_SECRET/);
    expect(text).not.toMatch(/echo[^\n]*\$\{?SSI_CANDIDATE_TEST_EVIDENCE_HMAC_SECRET/);
    expect(text).toContain("grep -q 'no command specified'");
    expect(text).toContain("sed 's/##vso\\[/##vso_[/g'");
  });

  it('names the invalid image parameter and never leaves the artifact step without a folder', () => {
    const text = pipeline();
    expect(text).toContain('check_reference sourceReference "${SOURCE_REFERENCE}"');
    expect(text).toContain('check_reference candidateReference "${CANDIDATE_REFERENCE}"');
    expect(text).toContain('(received: $(shown "${reference}"))');
    // The shown value is one line, bounded and cannot carry a logging command.
    expect(text).toContain("shown() { printf '%s' \"$1\" | head -c 200 | sed 's/##vso\\[/##vso_[/g'; }");
    expect(text).toContain('printf \'%s\\n\' "$1" > "${EVIDENCE_DIR}/failure.txt"');
  });

  it('runs the test containers isolated and never privileged', () => {
    const text = pipeline();
    expect(text).toContain('--network none');
    expect(text).toContain('--memory 512m --memory-swap 512m --cpus 1 --pids-limit 256');
    expect(text).toContain('--security-opt no-new-privileges:true');
    expect(text).not.toContain('--privileged');
    expect(text).not.toContain('docker.sock');
    expect(text).not.toContain('docker exec');
    expect(text).not.toContain('--publish');
    const runBlock = text.slice(text.indexOf('docker run --detach'), text.indexOf('"${reference}" >/dev/null'));
    expect(runBlock).not.toMatch(/\s-p\s/);
    expect(runBlock).not.toMatch(/--cap-add|--volume|\s-v\s/);
  });

  it('lists packages without the vulnerability database and with the Harbor CA', () => {
    const text = pipeline();
    expect(text).toContain('--scanners license');
    expect(text).toContain('--pkg-types os');
    expect(text).toContain('--image-src remote');
    expect(text).toContain('-e SSL_CERT_FILE=/work/certs/harbor-ca.pem');
    expect(text).toContain('TRIVY_IMAGE: ghcr.io/aquasecurity/trivy@sha256:');
  });

  it('delivers failed results too and never ends green when SSI was unreachable', () => {
    const text = pipeline();
    expect(text.indexOf('node "${TOOL}" deliver')).toBeLessThan(text.indexOf("[[ \"${RESULT}\" == 'passed' ]]"));
    expect(text).toContain("##vso[task.complete result=SucceededWithIssues;]");
    expect(text).toContain('SSI_CANDIDATE_TEST_EVIDENCE_HMAC_SECRET: $(SSI_CANDIDATE_TEST_EVIDENCE_HMAC_SECRET)');
  });

  it('cleans up only its own containers and temporary files, always', () => {
    const text = pipeline();
    expect(text).toContain('trap cleanup EXIT');
    expect(text).toContain('--label "ssi.candidate-test=${RUN_ID}"');
    expect(text).toContain('--filter "label=ssi.candidate-test=${RUN_ID}"');
    expect(text).toContain('rm -rf "${AGENT_TEMPDIRECTORY:?AGENT_TEMPDIRECTORY is required}/${RUN_ID}"');
    expect(text).toMatch(/displayName: 'Cleanup \(only this run\)'\n\s+condition: always\(\)/);
  });
});

describe('candidate test summary', () => {
  it('renders a markdown table without breaking cells or passing HTML through', () => {
    const markdown = renderSummary(evidence);
    expect(markdown).toContain('## SSI candidate test — PASSED');
    expect(markdown).toContain('| startup | pass | Starts   like bthe/b source |');
    expect(markdown).toContain('| zlib | changed | 1.3 | 2.0 | major version |');
    expect(markdown).not.toContain('Image facts');
  });

  it('adds the image facts when the evidence carries them', () => {
    const digest = (letter) => `sha256:${letter.repeat(64)}`;
    const markdown = renderSummary({
      ...evidence,
      imageFacts: {
        source: { sizeBytes: 48_000_000, diffIds: [digest('1')], config: {} },
        candidate: { sizeBytes: null, diffIds: [digest('1'), digest('2')], config: {} },
      },
    });
    expect(markdown).toContain('- Layers: 1 → 2');
    expect(markdown).toContain('- Size: 48.0 MB → unknown');
  });
});

describe('candidate test delivery', () => {
  let server;
  let directory;

  afterEach(async () => {
    if (server) await new Promise((resolve) => server.close(resolve));
    if (directory) rmSync(directory, { recursive: true, force: true });
    server = undefined;
    directory = undefined;
  });

  async function startServer(handler) {
    server = createServer((request, response) => {
      let body = '';
      request.setEncoding('utf8');
      request.on('data', (chunk) => {
        body += chunk;
      });
      request.on('end', () => handler(request, response, body));
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    return `http://127.0.0.1:${server.address().port}/api/v1`;
  }

  function evidenceFile(value = evidence) {
    directory = mkdtempSync(join(tmpdir(), 'ssi-candidate-'));
    const path = join(directory, 'candidate-test-result.json');
    writeFileSync(path, JSON.stringify(value));
    return path;
  }

  const options = (apiBaseUrl, file) => ({
    file,
    'job-id': 'RM-EXEC-0004',
    'api-base-url': apiBaseUrl,
    'worker-id': 'LinuxAgent1:build-agent-01',
    'allow-http': 'true',
  });
  const env = { SSI_CANDIDATE_TEST_EVIDENCE_HMAC_SECRET: SECRET };
  const noSleep = { env, sleep: async () => {} };

  it('signs the exact body for the candidate-test purpose and posts it to the worker endpoint', async () => {
    let received;
    const baseUrl = await startServer((request, response, body) => {
      received = {
        url: request.url,
        auth: verifyWorkerEvidenceRequest({
          jobId: 'RM-EXEC-0004',
          rawBody: body,
          headers: request.headers,
          secret: SECRET,
          purpose: EVIDENCE_PURPOSE.CANDIDATE_TEST,
        }),
      };
      response.writeHead(200, { 'Content-Type': 'application/json' });
      response.end('{}');
    });

    const result = await deliver(options(baseUrl, evidenceFile()), noSleep);
    expect(result).toEqual({ delivered: true, status: 200, attempts: 1 });
    expect(received.url).toBe('/api/v1/remediation/RM-EXEC-0004/worker-candidate-test');
    expect(received.auth.workerId).toBe('LinuxAgent1:build-agent-01');
  });

  it('retries transient failures and reports SSI as unreachable afterwards', async () => {
    let calls = 0;
    const baseUrl = await startServer((_request, response) => {
      calls += 1;
      response.writeHead(503, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify({ message: 'maintenance' }));
    });
    const result = await deliver(options(baseUrl, evidenceFile()), noSleep);
    expect(calls).toBe(3);
    expect(result).toMatchObject({ delivered: false, permanent: false, message: 'maintenance', attempts: 3 });
  });

  it('does not retry a rejection', async () => {
    let calls = 0;
    const baseUrl = await startServer((_request, response) => {
      calls += 1;
      response.writeHead(422, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify({ message: 'The tested candidate is not the verified output digest of this job.' }));
    });
    const result = await deliver(options(baseUrl, evidenceFile()), noSleep);
    expect(calls).toBe(1);
    expect(result).toMatchObject({ delivered: false, permanent: true, status: 422 });
  });

  it('refuses insecure or unsafe configurations before sending anything', async () => {
    const file = evidenceFile();
    await expect(deliver({ ...options('http://ssi.example/api/v1', file), 'allow-http': 'false' }, noSleep)).rejects.toThrow(/HTTPS/);
    await expect(deliver(options('https://user:pass@ssi.example/api/v1', file), noSleep)).rejects.toThrow(/credentials/);
    await expect(deliver(options('https://ssi.example/api/v1', file), { env: {}, sleep: async () => {} })).rejects.toThrow(/Secret/);
    await expect(deliver({ ...options('https://ssi.example/api/v1', file), 'job-id': 'RM-EXEC-0009' }, noSleep)).rejects.toThrow(
      /another remediation job/,
    );
  });
});
