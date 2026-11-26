import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { assembleResult, deliver } from '../../scripts/os-template-evidence.mjs';
import { MemoryRemediationStore } from '../server/remediationStore.js';
import { buildRunRequestBody } from './azureDevOps.js';
import { createOsTemplateBuild, decideOsTemplate } from './osTemplate.js';
import { PipelineRunError } from './pipelineRuns.js';
import {
  authorizePermission,
  isMachineRoute,
  permissionForRoute,
  permissionsForRoles,
} from './rbac.js';
import { ALL_TENANTS } from './tenancy.js';
import { EVIDENCE_PURPOSE, verifyWorkerEvidenceRequest } from './workerEvidenceAuth.js';
import { planOsTemplateRun, workerActionsView } from './workerPipelineActions.js';

// How an OS template build request moves through SSI: permissions, the worker pipeline plan,
// the store and the signed delivery (src/lib/osTemplate.js holds the rules themselves).
const SECRET = 'os-template-secret-with-at-least-32-bytes';
const INPUT = {
  isoFile: 'WS2025_EVAL_en-us.iso',
  isoSha256: '7b052573ba7894c9924e3e87ba732ccd354d18cb75a883efa9b900ea125bfd51',
  imageIndex: 2,
  product: 'Windows Server 2025',
  templateName: 'ssi-ws2025-std-de',
};
const request = (id = 'OST-0001') =>
  createOsTemplateBuild({ id, input: INPUT, requestedBy: 'def.op' });
const route = (method, path) => permissionForRoute(method, ['api', 'v1', ...path.split('/')]);
const can = (role, permission) => {
  try {
    authorizePermission(
      { enforced: true, authenticated: true, permissions: permissionsForRoles([role]) },
      permission,
    );
    return true;
  } catch {
    return false;
  }
};

describe('OS template permissions', () => {
  it('let every role read, operators request and build, approvers decide', () => {
    expect(route('GET', 'os-templates')).toBe('os-template:read');
    expect(route('POST', 'os-templates')).toBe('os-template:build');
    expect(route('POST', 'os-templates/OST-0001/pipeline-runs')).toBe('os-template:build');
    expect(route('POST', 'os-templates/OST-0001/approve')).toBe('os-template:approve');
    expect(route('POST', 'os-templates/OST-0001/reject')).toBe('os-template:approve');
    expect(['viewer', 'operator', 'approver'].every((role) => can(role, 'os-template:read'))).toBe(
      true,
    );
    expect([
      can('viewer', 'os-template:build'),
      can('operator', 'os-template:build'),
      can('approver', 'os-template:build'),
    ]).toEqual([false, true, false]);
    expect([
      can('operator', 'os-template:approve'),
      can('approver', 'os-template:approve'),
      can('admin', 'os-template:approve'),
    ]).toEqual([false, true, true]);
  });

  it('exempt only the HMAC-signed worker route from user RBAC', () => {
    expect(isMachineRoute('POST', ['api', 'v1', 'os-templates', 'OST-0001', 'worker'])).toBe(true);
    expect(route('POST', 'os-templates/OST-0001/worker')).toBeNull();
    expect(isMachineRoute('GET', ['api', 'v1', 'os-templates', 'OST-0001', 'worker'])).toBe(false);
  });
});

describe('the Windows template worker run', () => {
  const worker = { workerApiBaseUrl: 'http://10.0.0.10:5021/api/v1' };

  it('takes every parameter from the request, as text Azure DevOps accepts', () => {
    const plan = planOsTemplateRun(request(), 'os-template-build', worker);
    expect(plan).toEqual({
      action: 'os-template-build',
      role: 'osTemplateWindows',
      templateParameters: {
        osTemplateBuildId: 'OST-0001',
        isoFile: 'WS2025_EVAL_en-us.iso',
        isoSha256: INPUT.isoSha256,
        imageIndex: '2',
        product: 'Windows Server 2025',
        templateName: 'ssi-ws2025-std-de',
        deliverToSsi: true,
        ssiApiBaseUrl: worker.workerApiBaseUrl,
        allowInsecurePocApi: true,
      },
    });
    expect(() =>
      buildRunRequestBody({ ref: 'refs/heads/main' }, plan.templateParameters),
    ).not.toThrow();
  });

  it('is not started for a request that is built or decided, nor without the worker address', () => {
    const rejected = decideOsTemplate(request(), {
      decision: 'reject',
      actorId: 'def.ap',
      reason: 'x',
    });
    expect(() => planOsTemplateRun(rejected, 'os-template-build', worker)).toThrow(
      /Rejected; it is not built again/,
    );
    expect(() => planOsTemplateRun(request(), 'os-template-build', {})).toThrow(
      /SSI_ADO_WORKER_API_BASE_URL/,
    );
    expect(() => planOsTemplateRun(request(), 'image-inspection', worker)).toThrow(
      PipelineRunError,
    );
  });

  it('is offered on the screen with a confirmation, once per pipeline', () => {
    const view = workerActionsView('os-template', request(), {
      enabled: true,
      pipelines: { osTemplateWindows: 4800 },
      plan: (action) => planOsTemplateRun(request(), action, worker),
    });
    expect(view.actions).toEqual([
      {
        action: 'os-template-build',
        role: 'osTemplateWindows',
        label: 'Build the template ISO',
        confirm: true,
        available: true,
        reason: '',
      },
    ]);
    const running = {
      ...request(),
      pipelineRuns: [{ role: 'osTemplateWindows', runId: 1, state: 'inProgress' }],
    };
    const busy = workerActionsView('os-template', running, {
      enabled: true,
      pipelines: { osTemplateWindows: 4800 },
      plan: () => ({}),
    });
    expect(busy.actions[0]).toMatchObject({
      available: false,
      reason: 'A run of this pipeline is in progress.',
    });
  });
});

describe('OS template requests in the memory store', () => {
  const audit = (summary) => ({
    id: summary,
    eventType: 'os-template.test',
    summary,
    tenantId: null,
  });

  it('creates, lists newest first and decides one request at a time, with its audit event', async () => {
    const store = new MemoryRemediationStore();
    expect([await store.nextOsTemplateBuildId(), await store.nextOsTemplateBuildId()]).toEqual([
      'OST-0001',
      'OST-0002',
    ]);
    await store.createOsTemplateBuild(request('OST-0001'), audit('created 1'));
    await store.createOsTemplateBuild(request('OST-0002'), audit('created 2'));
    await expect(store.createOsTemplateBuild(request('OST-0001'), audit('again'))).rejects.toThrow(
      /already exists/,
    );
    expect((await store.listOsTemplateBuilds()).map((build) => build.id)).toEqual([
      'OST-0002',
      'OST-0001',
    ]);

    const decided = await store.updateOsTemplateBuildWith('OST-0001', async (current) => ({
      build: decideOsTemplate(current, {
        decision: 'reject',
        actorId: 'def.ap',
        reason: 'wrong ISO',
      }),
      auditEvent: audit('rejected 1'),
    }));
    expect(decided.status).toBe('Rejected');
    expect((await store.getOsTemplateBuild('OST-0001')).decision.reason).toBe('wrong ISO');
    // Nothing to write: no change and no audit event.
    expect((await store.updateOsTemplateBuildWith('OST-0002', async () => null)).status).toBe(
      'Requested',
    );
    expect((await store.listAuditEvents({}, ALL_TENANTS)).map((event) => event.summary)).toEqual([
      'rejected 1',
      'created 2',
      'created 1',
    ]);
  });

  it('returns copies and never lets an update change the request ID', async () => {
    const store = new MemoryRemediationStore();
    await store.createOsTemplateBuild(request(), audit('created'));
    (await store.getOsTemplateBuild('OST-0001')).status = 'Approved';
    expect((await store.getOsTemplateBuild('OST-0001')).status).toBe('Requested');
    await expect(
      store.updateOsTemplateBuildWith('OST-0001', async (current) => ({
        build: { ...current, id: 'OST-9999' },
      })),
    ).rejects.toThrow(/must not change the build ID/);
  });
});

describe('the signed result delivery (scripts/os-template-evidence.mjs)', () => {
  let directory;
  let server;
  afterEach(async () => {
    if (directory) rmSync(directory, { recursive: true, force: true });
    if (server) await new Promise((resolve) => server.close(resolve));
    directory = undefined;
    server = undefined;
  });

  const file = (name, content) => {
    directory ||= mkdtempSync(join(tmpdir(), 'ssi-os-template-'));
    const path = join(directory, name);
    writeFileSync(path, content);
    return path;
  };

  it('wraps the manifest (with the BOM Windows PowerShell may write) into the result for the request', () => {
    const manifest = file(
      'template-manifest.json',
      `\uFEFF${JSON.stringify({ manifestVersion: 'ssi.os-template-manifest/v1', template: { name: 'x' } })}`,
    );
    const result = assembleResult(
      {
        manifest,
        'build-id': 'OST-0007',
        'location-host': 'WINBUILD01',
        'location-path': 'E:\\SSI-Image\\runs\\ado-1\\out\\x.iso',
        pipeline: 'SSI - OS Template (Windows)',
        'ado-build-id': '4711',
        agent: 'WINBUILD01',
      },
      { generatedAt: '2026-11-24T12:00:00.000Z' },
    );
    expect(result).toMatchObject({
      contractVersion: 'ssi.os-template-build/v1',
      buildId: 'OST-0007',
      location: { host: 'WINBUILD01' },
      manifest: { template: { name: 'x' } },
    });
    expect(() =>
      assembleResult({
        manifest,
        'build-id': 'RM-DRY-0001',
        'location-host': 'h',
        'location-path': 'p',
      }),
    ).toThrow(/OST-0001/);
    const other = file('other.json', '{"manifestVersion":"v0"}');
    expect(() =>
      assembleResult({
        manifest: other,
        'build-id': 'OST-0007',
        'location-host': 'h',
        'location-path': 'p',
      }),
    ).toThrow(/is not ssi.os-template-manifest\/v1/);
  });

  it('signs the exact body for the request ID and posts it to the worker route', async () => {
    let received;
    server = createServer((incoming, response) => {
      const chunks = [];
      incoming.on('data', (chunk) => chunks.push(chunk));
      incoming.on('end', () => {
        received = {
          url: incoming.url,
          headers: incoming.headers,
          body: Buffer.concat(chunks).toString('utf8'),
        };
        response.writeHead(200, { 'Content-Type': 'application/json' });
        response.end('{}');
      });
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${server.address().port}/api/v1`;
    const result = file(
      'ssi-result.json',
      JSON.stringify({ contractVersion: 'ssi.os-template-build/v1', buildId: 'OST-0007' }),
    );
    const outcome = await deliver(
      {
        file: result,
        'api-base-url': base,
        'allow-http': 'true',
        'worker-id': 'ado-4711-WINBUILD01',
      },
      { env: { SSI_OS_TEMPLATE_EVIDENCE_HMAC_SECRET: SECRET } },
    );
    expect(outcome).toMatchObject({ delivered: true, status: 200 });
    expect(received.url).toBe('/api/v1/os-templates/OST-0007/worker');
    const verify = (purpose) =>
      verifyWorkerEvidenceRequest({
        jobId: 'OST-0007',
        rawBody: received.body,
        headers: received.headers,
        secret: SECRET,
        purpose,
      });
    expect(verify(EVIDENCE_PURPOSE.OS_TEMPLATE).workerId).toBe('ado-4711-WINBUILD01');
    // Domain separation: the signature is worthless for another worker channel.
    expect(() => verify(EVIDENCE_PURPOSE.IMAGE_INSPECTION)).toThrow();
  });

  it('refuses to send without the secret, over plain HTTP unless allowed, or for no request', async () => {
    const result = file('ssi-result.json', JSON.stringify({ buildId: 'OST-0007' }));
    const options = {
      file: result,
      'api-base-url': 'http://ssi.internal/api/v1',
      'worker-id': 'agent',
    };
    await expect(deliver(options, { env: {} })).rejects.toThrow(
      /SSI_OS_TEMPLATE_EVIDENCE_HMAC_SECRET is required/,
    );
    await expect(
      deliver(options, { env: { SSI_OS_TEMPLATE_EVIDENCE_HMAC_SECRET: '$(SECRET)' } }),
    ).rejects.toThrow(/is required/);
    await expect(
      deliver(options, { env: { SSI_OS_TEMPLATE_EVIDENCE_HMAC_SECRET: SECRET } }),
    ).rejects.toThrow(/must use HTTPS/);
    const none = { ...options, file: file('none.json', '{}'), 'allow-http': 'true' };
    await expect(
      deliver(none, { env: { SSI_OS_TEMPLATE_EVIDENCE_HMAC_SECRET: SECRET } }),
    ).rejects.toThrow(/does not name an OS template/);
  });
});

describe('OS template download permissions', () => {
  it('let operators and approvers download, and the link stand on its one-time ticket', () => {
    expect(route('POST', 'os-templates/OST-0002/download-tickets')).toBe('os-template:download');
    expect(
      ['viewer', 'operator', 'approver'].map((role) => can(role, 'os-template:download')),
    ).toEqual([false, true, true]);
    expect(isMachineRoute('GET', ['api', 'v1', 'os-templates', 'OST-0002', 'downloads'])).toBe(
      true,
    );
    expect(isMachineRoute('POST', ['api', 'v1', 'os-templates', 'OST-0002', 'downloads'])).toBe(
      false,
    );
  });
});
