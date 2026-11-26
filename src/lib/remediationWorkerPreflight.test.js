import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

const pipelineFile = new URL('../../azure-pipelines-remediation-worker-preflight.yml', import.meta.url);

describe('remediation worker preflight pipeline', () => {
  it('remains manual and read-only', async () => {
    const pipeline = await readFile(pipelineFile, 'utf8');

    expect(pipeline).toMatch(/^trigger: none$/m);
    expect(pipeline).toMatch(/^pr: none$/m);
    expect(pipeline).toContain("executionAuthorized: false");
    expect(pipeline).toContain("patchAttempted: false");
    expect(pipeline).toContain("registryWriteAttempted: false");
    expect(pipeline).toContain("verificationScanAttempted: false");
    expect(pipeline).not.toMatch(/\bcopa\s+patch\b/);
    expect(pipeline).not.toMatch(/\s--push\b/);
    expect(pipeline).not.toMatch(/curl\s+-k\b/);
  });

  it('keeps the worker prerequisites explicit and does not download Copa at runtime', async () => {
    const pipeline = await readFile(pipelineFile, 'utf8');

    expect(pipeline).toContain('docker buildx inspect');
    expect(pipeline).toContain('COPA_EXPECTED_VERSION');
    expect(pipeline).toContain('Pre-provisioned Copa executable');
    expect(pipeline).toContain('HARBOR_ROBOT_SECRET');
    expect(pipeline).toContain('remediation-worker-preflight');
    expect(pipeline).toContain('default: system');
    expect(pipeline).toContain("if [[ \"${HARBOR_CA_CERT_PATH}\" == 'system' ]]; then");
    expect(pipeline).toContain('SSI_PREFLIGHT_SOURCE_REPOSITORY');
    expect(pipeline).toContain('SSI_PREFLIGHT_ROBOT_SECRET');
    expect(pipeline).toContain('is_unresolved_azure_macro');
    expect(pipeline).not.toContain('INPUT_SOURCE_REPOSITORY');
    expect(pipeline).not.toMatch(/\b(curl|wget)\b[^\n]*(copacetic|copa)/i);
  });
});
