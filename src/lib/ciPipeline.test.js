import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

// The quality gate every push to main passes before it is packaged (azure-pipelines.yml).
const pipeline = readFileSync(new URL('../../azure-pipelines.yml', import.meta.url), 'utf8');
const position = (displayName) => {
  const index = pipeline.indexOf(`displayName: '${displayName}'`);
  expect(index, displayName).toBeGreaterThan(-1);
  return index;
};

describe('CI quality gate', () => {
  it('runs every check before the build is packaged', () => {
    const order = [
      'Secret scan (gitleaks)',
      'Install dependencies',
      'Dependency audit (npm audit)',
      'Lint (ESLint)',
      'Unit tests (Vitest)',
      'Production build',
      'End-to-end tests (PostgreSQL)',
      'Remove the test database',
      'Archive Application Files',
    ].map(position);
    expect(order).toEqual([...order].sort((left, right) => left - right));
    expect(pipeline).toMatch(
      /- stage: Package\n\s+displayName: 'Package Files'\n\s+dependsOn: Quality\n\s+condition: succeeded\(\)/,
    );
  });

  it('keeps the artifact the Release consumes unchanged', () => {
    expect(pipeline).toContain("archiveFile: '$(Build.ArtifactStagingDirectory)/app.zip'");
    expect(pipeline).toContain("ArtifactName: 'drop'");
  });

  it('scans the committed files with a checksum-pinned gitleaks and never prints a finding', () => {
    expect(pipeline).toMatch(/GITLEAKS_VERSION: '\d+\.\d+\.\d+'/);
    expect(pipeline).toMatch(/GITLEAKS_LINUX_X64_SHA256: '[a-f0-9]{64}'/);
    expect(pipeline).toContain('sha256sum --check --status');
    expect(pipeline).toContain('git archive HEAD');
    expect(pipeline).toContain('--redact');
    expect(pipeline).not.toMatch(/\|\s*sh\b/);
  });

  it('fails on high runtime and critical build vulnerabilities', () => {
    expect(pipeline).toContain('npm audit --omit=dev --audit-level=high');
    expect(pipeline).toContain('npm audit --audit-level=critical');
  });

  it('runs the end-to-end suite on a local-only, throwaway database that is always removed', () => {
    expect(pipeline).toContain('-p 127.0.0.1::5432');
    expect(pipeline).toContain('npm run -s test:e2e:tenancy');
    expect(pipeline).toMatch(/displayName: 'Remove the test database'\n\s+condition: always\(\)/);
    expect(pipeline).not.toMatch(/POSTGRES_PASSWORD=(?!"\$\{PASSWORD\}")/);
    expect(pipeline).toMatch(
      /E2E_POSTGRES_IMAGE: 'docker\.io\/library\/postgres@sha256:[a-f0-9]{64}'/,
    );
  });

  it('installs Node 22 with the supported task', () => {
    expect(pipeline).toMatch(
      /- task: UseNode@1\n\s+displayName: 'Use Node 22'\n\s+inputs:\n\s+version: '22\.x'/,
    );
    expect(pipeline).not.toContain('NodeTool@0');
  });
});
