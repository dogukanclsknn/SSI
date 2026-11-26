import { describe, expect, it } from 'vitest';
import { buildAzureDevOpsConfig } from '../lib/azureDevOps.js';
import { createAzureDevOpsClient } from './azureDevOpsClient.js';

const TOKEN = 'secret-token-value-'.padEnd(52, 'x');
const config = buildAzureDevOpsConfig({
  SSI_ADO_ORG_URL: 'https://example-org.visualstudio.com',
  SSI_ADO_PROJECT: 'SecureImages',
  SSI_ADO_PAT: TOKEN,
  SSI_ADO_PIPELINE_CANDIDATE_TEST: '412',
});

function reply(status, body, contentType = 'application/json; charset=utf-8') {
  return {
    status,
    headers: { get: (name) => (name.toLowerCase() === 'content-type' ? contentType : null) },
    text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
  };
}

function fakeFetch(handler) {
  const calls = [];
  const impl = async (url, options) => {
    calls.push({ url, options });
    return handler(url, options);
  };
  return { impl, calls };
}

describe('createAzureDevOpsClient', () => {
  it('reads bounded progress from the build timeline without forwarding raw logs', async () => {
    const { impl, calls } = fakeFetch(() => reply(200, { records: [
      { type: 'Task', state: 'completed', name: 'Check' },
      { type: 'Task', state: 'inProgress', name: 'Copy', issues: [{ message: TOKEN }] },
    ] }));
    const client = createAzureDevOpsClient(config, { fetchImpl: impl });
    const progress = await client.getRunProgress('candidateTest', 900);
    expect(calls[0].url).toBe('https://example-org.visualstudio.com/SecureImages/_apis/build/builds/900/timeline?api-version=7.1');
    expect(progress).toEqual({ percent: 50, currentStep: 'Copy' });
    expect(JSON.stringify(progress)).not.toContain(TOKEN);
  });
  it('starts a run on the configured pipeline and branch, with the token only in the header', async () => {
    const { impl, calls } = fakeFetch(() =>
      reply(200, { id: 900, state: 'inProgress', name: 'r1' }),
    );
    const client = createAzureDevOpsClient(config, { fetchImpl: impl });
    const run = await client.runPipeline('candidateTest', { remediationJobId: 'RM-EXEC-0004' });
    expect(run).toMatchObject({ id: 900, state: 'inProgress' });
    const [{ url, options }] = calls;
    expect(url).toBe(
      'https://example-org.visualstudio.com/SecureImages/_apis/pipelines/412/runs?api-version=7.1',
    );
    expect(options.method).toBe('POST');
    expect(options.redirect).toBe('manual');
    expect(options.headers.Authorization).toBe(
      `Basic ${Buffer.from(`:${TOKEN}`).toString('base64')}`,
    );
    expect(url).not.toContain(TOKEN);
    expect(JSON.parse(options.body)).toEqual({
      resources: { repositories: { self: { refName: 'refs/heads/main' } } },
      templateParameters: { remediationJobId: 'RM-EXEC-0004' },
    });
  });

  it('never calls Azure DevOps for a pipeline that is not configured', async () => {
    const { impl, calls } = fakeFetch(() => reply(200, { id: 1 }));
    const client = createAzureDevOpsClient(config, { fetchImpl: impl });
    await expect(client.runPipeline('controlledPublish', {})).rejects.toMatchObject({
      code: 'ado_pipeline_not_configured',
    });
    expect(calls).toHaveLength(0);
  });

  it('reports a token Azure DevOps did not accept (203 sign-in page, redirect, 401)', async () => {
    for (const response of [
      reply(203, '<html>sign in</html>', 'text/html'),
      reply(302, ''),
      reply(401, ''),
    ]) {
      const client = createAzureDevOpsClient(config, { fetchImpl: async () => response });
      const error = await client.getRun('candidateTest', 5).catch((caught) => caught);
      expect(error.code).toBe('ado_auth');
      expect(error.message).not.toContain(TOKEN);
    }
  });

  it('maps permission, missing pipeline and refused requests with one line of the Azure DevOps message', async () => {
    const cases = [
      [403, 'ado_forbidden'],
      [404, 'ado_not_found'],
      [400, 'ado_rejected'],
      [500, 'ado_unavailable'],
    ];
    for (const [status, code] of cases) {
      const client = createAzureDevOpsClient(config, {
        fetchImpl: async () => reply(status, { message: `Detail for ${status}\nsecond line` }),
      });
      const error = await client.getRun('candidateTest', 5).catch((caught) => caught);
      expect(error.code).toBe(code);
      expect(error.message).not.toContain('\n');
    }
  });

  it('reports an unreachable or slow Azure DevOps without hanging', async () => {
    const slow = createAzureDevOpsClient(config, {
      timeoutMs: 20,
      fetchImpl: (url, { signal }) =>
        new Promise((_, reject) => signal.addEventListener('abort', () => reject(signal.reason))),
    });
    await expect(slow.getRun('candidateTest', 5)).rejects.toMatchObject({
      code: 'ado_unreachable',
    });
    const down = createAzureDevOpsClient(config, {
      fetchImpl: async () => Promise.reject(new TypeError('fetch failed')),
    });
    await expect(down.getRun('candidateTest', 5)).rejects.toMatchObject({
      code: 'ado_unreachable',
    });
  });

  it('refuses oversized or malformed answers', async () => {
    const big = createAzureDevOpsClient(config, {
      fetchImpl: async () => reply(200, 'x'.repeat(1024 * 1024 + 1)),
    });
    await expect(big.getRun('candidateTest', 5)).rejects.toMatchObject({
      code: 'ado_bad_response',
    });
    const broken = createAzureDevOpsClient(config, {
      fetchImpl: async () => reply(200, '{not json'),
    });
    await expect(broken.getRun('candidateTest', 5)).rejects.toMatchObject({
      code: 'ado_bad_response',
    });
  });

  it('does nothing when the integration is not configured', async () => {
    const { impl, calls } = fakeFetch(() => reply(200, {}));
    const client = createAzureDevOpsClient(buildAzureDevOpsConfig({}), { fetchImpl: impl });
    expect(client.enabled).toBe(false);
    await expect(client.getRun('candidateTest', 1)).rejects.toMatchObject({
      code: 'ado_not_configured',
    });
    expect(calls).toHaveLength(0);
  });

  it('checks every pipeline role read-only and reports the unconfigured ones', async () => {
    const { impl, calls } = fakeFetch(() => reply(200, { id: 412, name: 'SSI - Candidate Test' }));
    const client = createAzureDevOpsClient(config, { fetchImpl: impl });
    const results = await client.checkPipelines();
    expect(results.find((item) => item.role === 'candidateTest')).toMatchObject({
      ok: true,
      name: 'SSI - Candidate Test',
    });
    expect(
      results.filter((item) => !item.ok).every((item) => item.error === 'Not configured'),
    ).toBe(true);
    expect(calls.every((call) => call.options.method === 'GET')).toBe(true);
  });
});

// OS template downloads (src/lib/osTemplateDownloads.js) and retention leases.
describe('artifact downloads and retention leases', () => {
  const ubuntuConfig = buildAzureDevOpsConfig({
    SSI_ADO_ORG_URL: 'https://example-org.visualstudio.com',
    SSI_ADO_PROJECT: 'SecureImages',
    SSI_ADO_PAT: TOKEN,
    SSI_ADO_PIPELINE_OS_TEMPLATE_UBUNTU: '4682',
  });
  const ARTIFACT =
    'https://example-org.visualstudio.com/SecureImages/_apis/build/builds/883972/artifacts?artifactName=os-template-ubuntu-ova&api-version=7.1';
  const described = () => reply(200, { id: 7, name: 'os-template-ubuntu-ova' });
  const zip = (status, headers = {}, body = 'PK zip bytes of the artifact') => {
    const all = {
      'content-type': 'application/zip',
      'content-length': String(body.length),
      ...headers,
    };
    return {
      status,
      headers: { get: (name) => all[name.toLowerCase()] ?? null },
      body: new Response(body).body,
      text: async () => body,
    };
  };
  const read = async (stream) => {
    let text = '';
    for await (const chunk of stream) text += chunk.toString();
    return text;
  };
  const route = (routes) => (url) => (routes[url] || (() => zip(404)))();

  // Production, 2026-11-25: "Get Artifact" with Accept: application/zip streamed the artifact.
  it('streams the zip of "Get Artifact", with the token sent to the organization only', async () => {
    const { impl, calls } = fakeFetch(route({ [ARTIFACT]: () => zip(200) }));
    const client = createAzureDevOpsClient(ubuntuConfig, { fetchImpl: impl });
    const opened = await client.openArtifact(883972, 'os-template-ubuntu-ova');
    expect(await read(opened.stream)).toBe('PK zip bytes of the artifact');
    expect(opened.contentLength).toBe(28);
    expect(calls.map((call) => call.url)).toEqual([ARTIFACT]);
    expect(calls[0].options.headers).toMatchObject({ Accept: 'application/zip' });
    expect(calls[0].options.headers.Authorization).toMatch(/^Basic /);
    expect(calls[0].options.redirect).toBe('manual');
  });

  // Production, 2026-11-25: the artifact zip comes chunked, without a Content-Length. That
  // was read as 0 bytes, so every download was declared empty and cut after the first chunk.
  it('streams a zip sent without a Content-Length, its length unknown (not 0)', async () => {
    const body = 'PK'.padEnd(64 * 1024, 'x');
    const chunked = () => {
      const response = zip(200, {}, body);
      const all = { 'content-type': 'application/zip' };
      return { ...response, headers: { get: (name) => all[name.toLowerCase()] ?? null } };
    };
    const client = createAzureDevOpsClient(ubuntuConfig, {
      fetchImpl: fakeFetch(route({ [ARTIFACT]: chunked })).impl,
    });
    const opened = await client.openArtifact(883972, 'os-template-ubuntu-ova');
    expect(opened.contentLength).toBeNull();
    expect((await read(opened.stream)).length).toBe(64 * 1024);
  });

  // Production, 2026-11-25: the headers time limit stayed on the request and cut every
  // download after 60 seconds ("The operation was aborted due to timeout").
  it('limits the wait for the headers, never the length of the download', async () => {
    // Like fetch: the signal given with the request also aborts its body.
    const slow = (url, { signal }) => {
      let sent = 0;
      const body = new ReadableStream({
        async pull(controller) {
          if (signal.aborted) return controller.error(signal.reason);
          if (sent === 6) return controller.close();
          await new Promise((resolve) => setTimeout(resolve, 40));
          if (signal.aborted) return controller.error(signal.reason);
          sent += 1;
          controller.enqueue(new TextEncoder().encode('0123456789'));
        },
      });
      return {
        status: 200,
        headers: { get: (name) => (name === 'content-type' ? 'application/zip' : null) },
        body,
      };
    };
    const client = createAzureDevOpsClient(ubuntuConfig, {
      fetchImpl: slow,
      artifactHeadersTimeoutMs: 60,
    });
    // Six chunks 40 ms apart: 240 ms of body, four times the headers limit.
    const opened = await client.openArtifact(883972, 'os-template-ubuntu-ova');
    expect((await read(opened.stream)).length).toBe(60);

    const silent = createAzureDevOpsClient(ubuntuConfig, {
      fetchImpl: (url, { signal }) =>
        new Promise((resolve, reject) =>
          signal.addEventListener('abort', () => reject(signal.reason)),
        ),
      artifactHeadersTimeoutMs: 30,
    });
    await expect(silent.openArtifact(883972, 'os-template-ubuntu-ova')).rejects.toThrow(
      /could not be reached/,
    );
  });

  it('still ends the download when the caller gives up', async () => {
    const endless = (url, { signal }) => ({
      status: 200,
      headers: { get: (name) => (name === 'content-type' ? 'application/zip' : null) },
      body: new ReadableStream({
        async pull(controller) {
          await new Promise((resolve) => setTimeout(resolve, 10));
          if (signal.aborted) return controller.error(signal.reason);
          controller.enqueue(new TextEncoder().encode('x'));
        },
      }),
    });
    const caller = new AbortController();
    const client = createAzureDevOpsClient(ubuntuConfig, { fetchImpl: endless });
    const opened = await client.openArtifact(883972, 'os-template-ubuntu-ova', {
      signal: caller.signal,
    });
    setTimeout(() => caller.abort(new Error('browser left')), 50);
    await expect(read(opened.stream)).rejects.toThrow(/browser left/);
  });

  it('follows a redirect to Azure blob storage without the token', async () => {
    const blob = 'https://vsblobprodscussu5shard1.blob.core.windows.net/a/b?sig=x';
    const { impl, calls } = fakeFetch(
      route({ [ARTIFACT]: () => zip(302, { location: blob }), [blob]: () => zip(200) }),
    );
    const client = createAzureDevOpsClient(ubuntuConfig, { fetchImpl: impl });
    await read((await client.openArtifact(883972, 'os-template-ubuntu-ova')).stream);
    expect(calls.map((call) => call.url)).toEqual([ARTIFACT, blob]);
    expect(calls[1].options.headers.Authorization).toBeUndefined();
  });

  it.each([
    [
      'a redirect to another host (a sign-in page)',
      () => zip(302, { location: 'https://login.example.com/' }),
      /did not hand out the artifact/,
    ],
    [
      'a plain-http redirect',
      () => zip(302, { location: 'http://x.blob.core.windows.net/a' }),
      /did not hand out the artifact/,
    ],
    [
      'an HTML page instead of a zip',
      () => zip(200, { 'content-type': 'text/html' }, '<html>'),
      /did not accept the token/,
    ],
    [
      'an empty archive',
      () => zip(200, {}, 'PK\x05\x06'.padEnd(22, '\0')),
      /empty archive for os-template-ubuntu-ova of run 883972/,
    ],
    [
      'a removed artifact',
      () => zip(404, { 'content-type': 'application/json' }, '{}'),
      /no longer in Azure DevOps/,
    ],
  ])('refuses %s', async (_, handler, message) => {
    const client = createAzureDevOpsClient(ubuntuConfig, {
      fetchImpl: fakeFetch(route({ [ARTIFACT]: handler })).impl,
    });
    await expect(client.openArtifact(883972, 'os-template-ubuntu-ova')).rejects.toThrow(message);
  });

  it('refuses an artifact name or run that could reach another address', async () => {
    const client = createAzureDevOpsClient(ubuntuConfig, {
      fetchImpl: fakeFetch(() => described()).impl,
    });
    await expect(client.openArtifact(883972, '../x')).rejects.toThrow(/artifact name/);
    await expect(client.openArtifact('1; drop', 'os-template-ubuntu-ova')).rejects.toThrow(
      /run ID/,
    );
  });

  it('checks that the artifact still exists, in a message for the screen', async () => {
    const found = createAzureDevOpsClient(ubuntuConfig, { fetchImpl: async () => described() });
    await expect(found.getArtifact(883972, 'os-template-ubuntu-ova')).resolves.toEqual({
      name: 'os-template-ubuntu-ova',
      id: 7,
    });
    const gone = createAzureDevOpsClient(ubuntuConfig, {
      fetchImpl: async () => reply(404, { message: 'not found' }),
    });
    await expect(gone.getArtifact(883972, 'os-template-ubuntu-ova')).rejects.toThrow(
      'Azure DevOps run 883972 has no artifact os-template-ubuntu-ova (removed by retention, or never published under that name).',
    );
  });

  it('retains the run of an approved template with a lease on the configured pipeline', async () => {
    const { impl, calls } = fakeFetch(() =>
      reply(200, [
        { leaseId: 51, runId: 883972, definitionId: 4682, validUntil: '2126-11-25T00:00:00Z' },
      ]),
    );
    const client = createAzureDevOpsClient(ubuntuConfig, { fetchImpl: impl });
    await expect(
      client.addRetentionLease({
        role: 'osTemplateUbuntu',
        runId: 883972,
        ownerId: 'SSI:OST-0002',
      }),
    ).resolves.toEqual({
      leaseId: 51,
      runId: 883972,
      definitionId: 4682,
      validUntil: '2126-11-25T00:00:00Z',
    });
    expect(calls[0].url).toBe(
      'https://example-org.visualstudio.com/SecureImages/_apis/build/retention/leases?api-version=7.1',
    );
    expect(JSON.parse(calls[0].options.body)).toEqual([
      {
        daysValid: 36500,
        definitionId: 4682,
        ownerId: 'SSI:OST-0002',
        protectPipeline: false,
        runId: 883972,
      },
    ]);
  });
});
