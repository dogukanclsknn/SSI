import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { runBash, stepEnv, stepScript } from './pipelineSteps.testkit.js';
import { EVIDENCE_PURPOSE, verifyWorkerEvidenceRequest } from './workerEvidenceAuth.js';
import { assertReceiptSigner, authenticateWorkerReceipt } from './workerReceiptAuth.js';

// The receipt signing the publish and onboarding workers run, executed as the agent runs it
// and checked with the verifier the SSI server uses (src/lib/workerReceiptAuth.js).
// Test-only value, built so no scanner mistakes it for a credential.
const SECRET = 'receipt-signing-test-'.padEnd(48, '0');

const channels = [
  {
    name: 'controlled publish',
    file: '../../azure-pipelines-controlled-publish.yml',
    step: 'Publish approved digest and submit receipt',
    secretVariable: 'SSI_PUBLISH_RECEIPT_HMAC_SECRET',
    subjectVariable: 'PUBLISH_REQUEST_ID',
    subject: 'PUB-0042',
    purpose: EVIDENCE_PURPOSE.PUBLISH_RECEIPT,
    otherPurpose: EVIDENCE_PURPOSE.ONBOARD_RECEIPT,
  },
  {
    name: 'onboarding import',
    file: '../../azure-pipelines-onboard-import.yml',
    step: 'Import external image into quarantine and submit receipt',
    secretVariable: 'SSI_ONBOARD_RECEIPT_HMAC_SECRET',
    subjectVariable: 'ONBOARDING_REQUEST_ID',
    subject: 'ONB-0042',
    purpose: EVIDENCE_PURPOSE.ONBOARD_RECEIPT,
    otherPurpose: EVIDENCE_PURPOSE.PUBLISH_RECEIPT,
  },
];

describe.each(channels)('$name worker receipt signing', (channel) => {
  const pipeline = readFileSync(new URL(channel.file, import.meta.url), 'utf8');
  const script = stepScript(pipeline, channel.step);
  // From the worker ID to the end of sign_receipt: the part of the step that signs.
  const signing = script.match(
    /^WORKER_ID="\$\(printf[\s\S]*?^sign_receipt\(\) \{[\s\S]*?^\}\n/m,
  )?.[0];
  let directory;

  afterEach(() => {
    if (directory) rmSync(directory, { recursive: true, force: true });
    directory = undefined;
  });

  function sign(body, env = {}) {
    directory = mkdtempSync(join(tmpdir(), 'ssi-receipt-'));
    const file = join(directory, 'receipt.json');
    writeFileSync(file, body);
    const result = runBash(
      `set -euo pipefail\n${signing}\nsign_receipt "$RECEIPT"\nprintf '%s\\n' "\${RECEIPT_CURL_HEADERS[@]}"`,
      {
        RECEIPT: file,
        AGENT_NAME: 'Build Agent 1',
        AGENT_MACHINENAME: 'build-01',
        [channel.subjectVariable]: channel.subject,
        [channel.secretVariable]: SECRET,
        ...env,
      },
    );
    if (!result.ok) return { ok: false, output: result.output };
    const lines = result.output.trim().split('\n');
    const headers = {};
    for (let index = 0; index < lines.length; index += 2) {
      expect(lines[index]).toBe('-H');
      const [name, ...value] = lines[index + 1].split(': ');
      headers[name] = value.join(': ');
    }
    return { ok: true, headers };
  }

  it('maps the secret into the step and sends no legacy token', () => {
    expect(signing).toBeTruthy();
    expect(stepEnv(pipeline, channel.step)[channel.secretVariable]).toBe(
      `$(${channel.secretVariable})`,
    );
    expect(pipeline).not.toMatch(/RECEIPT_TOKEN/);
  });

  it('produces a signature the SSI server accepts, naming a valid worker ID', () => {
    const body = JSON.stringify({ requestId: channel.subject, workerId: 'Build-Agent-1:build-01' });
    const { ok, headers } = sign(body);
    expect(ok).toBe(true);
    const authentication = authenticateWorkerReceipt({
      label: 'Receipt',
      subject: channel.subject,
      rawBody: body,
      headers,
      purpose: channel.purpose,
      hmacSecret: SECRET,
      legacyTokenHeader: 'x-unused',
    });
    expect(authentication.workerId).toBe('Build-Agent-1:build-01');
    expect(() => assertReceiptSigner(authentication, JSON.parse(body))).not.toThrow();
  });

  it('cannot be reused for another request, channel or body', () => {
    const body = JSON.stringify({ requestId: channel.subject });
    const { headers } = sign(body);
    const verify = (overrides) => () =>
      verifyWorkerEvidenceRequest({
        jobId: channel.subject,
        rawBody: body,
        headers,
        secret: SECRET,
        purpose: channel.purpose,
        ...overrides,
      });
    expect(verify({})).not.toThrow();
    expect(verify({ jobId: `${channel.subject}9` })).toThrow();
    expect(verify({ purpose: channel.otherPurpose })).toThrow();
    expect(verify({ rawBody: `${body} ` })).toThrow();
  });

  it('refuses to sign without a secret of at least 32 bytes and never prints it', () => {
    const short = sign('{}', { [channel.secretVariable]: 'short' });
    expect(short.ok).toBe(false);
    expect(short.output).toContain(`${channel.secretVariable} must contain at least 32 bytes.`);
    expect(short.output).not.toContain('short\n');
    const signed = sign('{}');
    expect(JSON.stringify(signed.headers)).not.toContain(SECRET);
  });
});
