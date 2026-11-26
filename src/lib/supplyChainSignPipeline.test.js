import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  parameterValues,
  pipelineVariable,
  runBash,
  stepEnv,
  stepScript,
} from './pipelineSteps.testkit.js';

const pipeline = readFileSync(
  new URL('../../azure-pipelines-supply-chain-sign.yml', import.meta.url),
  'utf8',
);
const VALIDATE_STEP = 'Validate signing inputs';
const INSTALL_STEP = 'Install pinned signing tools (checksum verified)';
const SIGN_STEP = 'Sign + SBOM + attest + verify + (optional) post to SSI';
const DIGEST = `sha256:${'a'.repeat(64)}`;
const SECRET_NAMES = [
  'COSIGN_PRIVATE_KEY',
  'COSIGN_PASSWORD',
  'COSIGN_PUBLIC_KEY',
  'HARBOR_ROBOT_SECRET',
  'SSI_SUPPLY_CHAIN_EVIDENCE_HMAC_SECRET',
];

function validateInputs(overrides = {}) {
  return runBash(stepScript(pipeline, VALIDATE_STEP), {
    APPROVED_REPOSITORY: 'approved/nginx',
    APPROVED_DIGEST: DIGEST,
    SOURCE_DIGEST: '',
    REMEDIATION_JOB_ID: 'RM-EXEC-0005',
    ...overrides,
  });
}

describe('supply-chain sign pipeline inputs', () => {
  it('signs only repositories in the approved catalog', () => {
    expect(validateInputs().ok).toBe(true);
    expect(validateInputs({ APPROVED_REPOSITORY: 'approved/payments/api' }).ok).toBe(true);
    for (const repository of [
      'onboarded/nginx',
      'approved',
      'approved/',
      'approved/../onboarded/nginx',
      'approved//nginx',
      'approved/Nginx',
      'ssi-test-alpine',
    ]) {
      const result = validateInputs({ APPROVED_REPOSITORY: repository });
      expect(result.ok, repository).toBe(false);
      expect(result.output).toContain('approvedRepository must be a repository under approved/');
    }
  });

  it('rejects tags and malformed identifiers before any secret is in reach', () => {
    expect(validateInputs({ APPROVED_DIGEST: 'latest' }).output).toContain(
      'approvedDigest must be a complete immutable sha256 digest',
    );
    expect(validateInputs({ SOURCE_DIGEST: 'sha256:abc' }).output).toContain(
      'sourceDigest must be empty or a complete sha256 digest.',
    );
    expect(validateInputs({ REMEDIATION_JOB_ID: 'RM-DRY-0007' }).output).toContain(
      'remediationJobId must be empty',
    );
    expect(validateInputs({ SOURCE_DIGEST: DIGEST, REMEDIATION_JOB_ID: '' }).ok).toBe(true);
  });

  it('accepts only the SSI addresses listed in the pipeline and never disables TLS checks', () => {
    expect(parameterValues(pipeline, 'ssiApiBaseUrl')).toEqual([
      'http://10.0.0.10:5021/api/v1',
      'http://ssi.example.com/api/v1',
    ]);
    expect(pipeline).toMatch(/- name: allowInsecurePocApi\n(?: {4}[^\n]*\n)*? {4}default: false/);
    // Only Rekor is skipped (key-based signing for the internal Harbor); TLS is always verified.
    expect(pipeline).not.toMatch(/--insecure(?!-ignore-tlog=true)/);
  });
});

describe('supply-chain sign pipeline tools', () => {
  let directory;

  afterEach(() => {
    if (directory) rmSync(directory, { recursive: true, force: true });
    directory = undefined;
  });

  it('pins each tool by version and by the checksum published with its release', () => {
    expect(pipelineVariable(pipeline, 'SYFT_VERSION')).toBe('v1.20.0');
    expect(pipelineVariable(pipeline, 'SYFT_LINUX_AMD64_SHA256')).toBe(
      '689e12c5cbf67521ce61b9c126068f9eaabe1223e77971b2fede50033ff6b5cc',
    );
    expect(pipelineVariable(pipeline, 'COSIGN_VERSION')).toBe('v2.4.1');
    expect(pipelineVariable(pipeline, 'COSIGN_LINUX_AMD64_SHA256')).toBe(
      '8b24b946dd5809c6bd93de08033bcf6bc0ed7d336b7785787c080f574b89249b',
    );
    expect(pipeline).not.toMatch(/\|\s*sh\b/);
    expect(pipeline).not.toContain('raw.githubusercontent.com');
  });

  it('downloads tools in a step that holds no secret, and the signing step downloads nothing', () => {
    const installEnv = Object.keys(stepEnv(pipeline, INSTALL_STEP));
    const validateEnv = Object.keys(stepEnv(pipeline, VALIDATE_STEP));
    for (const secret of SECRET_NAMES) {
      expect(installEnv).not.toContain(secret);
      expect(validateEnv).not.toContain(secret);
    }
    expect(Object.keys(stepEnv(pipeline, SIGN_STEP))).toContain('COSIGN_PRIVATE_KEY');
    const signScript = stepScript(pipeline, SIGN_STEP);
    expect(signScript).not.toContain('github.com');
    expect(signScript).toContain('was not installed by the verified install step.');
    expect(pipeline.indexOf(`displayName: '${INSTALL_STEP}'`)).toBeLessThan(
      pipeline.indexOf(`displayName: '${SIGN_STEP}'`),
    );
  });

  // Runs the install step's fetch_verified against a stubbed curl that writes `content`.
  function fetchWith(content, expected) {
    directory = mkdtempSync(join(tmpdir(), 'ssi-sign-tools-'));
    const script = stepScript(pipeline, INSTALL_STEP);
    const helper = script.match(/^fetch_verified\(\) \{\n[\s\S]*?^\}$/m)[0];
    const output = join(directory, 'tool');
    writeFileSync(join(directory, 'content'), content);
    return {
      output,
      result: runBash(
        `set -euo pipefail
curl() { local out=''; while [[ $# -gt 0 ]]; do [[ "$1" == '-o' ]] && out="$2"; shift; done; cp "${join(directory, 'content')}" "$out"; }
${helper}
fetch_verified https://github.com/example/tool "${expected}" "${output}"`,
        {},
      ),
    };
  }

  it('keeps a download only when its SHA-256 matches the pinned value', () => {
    const content = 'trusted release asset';
    const good = createHash('sha256').update(content).digest('hex');
    const accepted = fetchWith(content, good);
    expect(accepted.result.ok).toBe(true);
    expect(readFileSync(accepted.output, 'utf8')).toBe(content);

    const rejected = fetchWith('tampered asset', good);
    expect(rejected.result.ok).toBe(false);
    expect(rejected.result.status).toBe(3);
    expect(rejected.result.output).toContain('Checksum mismatch');
    expect(() => readFileSync(rejected.output)).toThrow();

    const unpinned = fetchWith(content, '');
    expect(unpinned.result.status).toBe(2);
    expect(unpinned.result.output).toContain('No pinned SHA-256');
  });
});
