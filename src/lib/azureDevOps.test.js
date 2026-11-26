import { describe, expect, it } from 'vitest';
import {
  authorizationHeader,
  buildAzureDevOpsConfig,
  buildRunRequestBody,
  describeAzureDevOpsConfig,
  parseRun,
  pipelineIdFor,
  runsUrl,
  runUrl,
} from './azureDevOps.js';

const TOKEN = 'a'.repeat(52);
const env = (extra = {}) => ({
  SSI_ADO_ORG_URL: 'https://example-org.visualstudio.com/',
  SSI_ADO_PROJECT: 'SecureImages',
  SSI_ADO_PAT: TOKEN,
  SSI_ADO_PIPELINE_CANDIDATE_TEST: '412',
  SSI_ADO_PIPELINE_IMAGE_INSPECTION: '415',
  ...extra,
});

describe('buildAzureDevOpsConfig', () => {
  it('is off and silent when nothing is set', () => {
    const config = buildAzureDevOpsConfig({});
    expect(config).toMatchObject({ requested: false, configured: false, problems: [] });
  });

  it('accepts a complete Azure DevOps Services configuration', () => {
    const config = buildAzureDevOpsConfig(env());
    expect(config.configured).toBe(true);
    expect(config.orgUrl).toBe('https://example-org.visualstudio.com');
    expect(config.ref).toBe('refs/heads/main');
    expect(config.pipelines).toEqual({ candidateTest: 412, imageInspection: 415 });
  });

  it('never exposes the token when the config is serialised or described', () => {
    const config = buildAzureDevOpsConfig(env());
    expect(config.token).toBe(TOKEN);
    expect(JSON.stringify(config)).not.toContain(TOKEN);
    expect(Object.keys(config)).not.toContain('token');
    expect(JSON.stringify(describeAzureDevOpsConfig(config))).not.toContain(TOKEN);
  });

  it('refuses any host other than Azure DevOps Services, plain http and credentials in the URL', () => {
    for (const url of [
      'https://evil.example.com',
      'http://example-org.visualstudio.com',
      'https://user:pw@dev.azure.com/org',
      'https://dev.azure.com.evil.io/org',
    ]) {
      const config = buildAzureDevOpsConfig(env({ SSI_ADO_ORG_URL: url }));
      expect(config.configured, url).toBe(false);
      expect(config.problems.join(' '), url).toMatch(/SSI_ADO_ORG_URL/);
    }
    expect(
      buildAzureDevOpsConfig(env({ SSI_ADO_ORG_URL: 'https://dev.azure.com/example-org' })).configured,
    ).toBe(true);
  });

  it('names what is missing without ever printing a value', () => {
    const config = buildAzureDevOpsConfig(
      env({ SSI_ADO_PAT: 'short', SSI_ADO_PIPELINE_CANDIDATE_TEST: 'abc' }),
    );
    expect(config.configured).toBe(false);
    expect(config.problems).toEqual(
      expect.arrayContaining([
        'SSI_ADO_PAT is missing or malformed.',
        expect.stringMatching(/SSI_ADO_PIPELINE_CANDIDATE_TEST/),
      ]),
    );
    expect(config.problems.join(' ')).not.toContain('short');
  });

  it('accepts the worker callback address and refuses one with credentials', () => {
    const ok = buildAzureDevOpsConfig(env({ SSI_ADO_WORKER_API_BASE_URL: 'http://10.0.0.10:5021/api/v1/' }));
    expect(ok.configured).toBe(true);
    expect(ok.workerApiBaseUrl).toBe('http://10.0.0.10:5021/api/v1');
    const bad = buildAzureDevOpsConfig(env({ SSI_ADO_WORKER_API_BASE_URL: 'https://u:p@ssi.example/api/v1' }));
    expect(bad.configured).toBe(false);
    expect(bad.problems.join(' ')).toMatch(/SSI_ADO_WORKER_API_BASE_URL/);
  });

  it('requires at least one pipeline and a branch ref', () => {
    const noPipelines = buildAzureDevOpsConfig({
      SSI_ADO_ORG_URL: 'https://dev.azure.com/x',
      SSI_ADO_PROJECT: 'P',
      SSI_ADO_PAT: TOKEN,
    });
    expect(noPipelines.problems).toContain('No SSI_ADO_PIPELINE_* definition ID is set.');
    expect(buildAzureDevOpsConfig(env({ SSI_ADO_PIPELINE_REF: 'main' })).configured).toBe(false);
  });
});

describe('requests', () => {
  const config = buildAzureDevOpsConfig(env());

  it('only builds URLs for configured pipelines', () => {
    expect(runsUrl(config, 'candidateTest')).toBe(
      'https://example-org.visualstudio.com/SecureImages/_apis/pipelines/412/runs?api-version=7.1',
    );
    expect(runUrl(config, 'imageInspection', 77)).toBe(
      'https://example-org.visualstudio.com/SecureImages/_apis/pipelines/415/runs/77?api-version=7.1',
    );
    expect(() => pipelineIdFor(config, 'controlledPublish')).toThrow(/not configured/);
    expect(() => runUrl(config, 'candidateTest', 'x')).toThrow(/run ID/);
  });

  it('sends the configured branch and single-line string parameters', () => {
    expect(
      buildRunRequestBody(config, { remediationJobId: 'RM-EXEC-0004', deliverToSsi: true }),
    ).toEqual({
      resources: { repositories: { self: { refName: 'refs/heads/main' } } },
      templateParameters: { remediationJobId: 'RM-EXEC-0004', deliverToSsi: 'true' },
    });
  });

  it('refuses bad parameter names, values and counts', () => {
    expect(() => buildRunRequestBody(config, { 'bad-name': 'x' })).toThrow(/parameter name/);
    expect(() => buildRunRequestBody(config, { a: 'line\nbreak' })).toThrow(/single line/);
    expect(() => buildRunRequestBody(config, { a: 3 })).toThrow(/single line/);
    expect(() => buildRunRequestBody(config, { a: 'x'.repeat(2049) })).toThrow(/single line/);
    expect(() =>
      buildRunRequestBody(
        config,
        Object.fromEntries(Array.from({ length: 21 }, (_, i) => [`p${i}`, 'x'])),
      ),
    ).toThrow(/At most/);
    expect(() => buildRunRequestBody(config, [])).toThrow(/object/);
  });

  it('builds a basic authorization header with an empty user name', () => {
    expect(authorizationHeader('abc')).toBe(`Basic ${Buffer.from(':abc').toString('base64')}`);
  });
});

describe('parseRun', () => {
  it('keeps the identifiers, state, result and an Azure DevOps web link only', () => {
    expect(
      parseRun({
        id: 869460,
        name: '20261105.3',
        state: 'completed',
        result: 'succeeded',
        createdDate: '2026-11-05T10:00:00Z',
        finishedDate: '2026-11-05T10:04:00Z',
        _links: {
          web: { href: 'https://example-org.visualstudio.com/SecureImages/_build/results?buildId=869460' },
        },
      }),
    ).toMatchObject({
      id: 869460,
      state: 'completed',
      result: 'succeeded',
      webUrl: expect.stringContaining('buildId=869460'),
    });
    expect(
      parseRun({ id: 1, state: 'weird', _links: { web: { href: 'https://evil.example.com/x' } } }),
    ).toMatchObject({
      state: 'unknown',
      result: null,
      webUrl: '',
    });
    expect(() => parseRun({})).toThrow(/unexpected run response/);
  });
});
