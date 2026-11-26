import { describe, expect, it } from 'vitest';
import { MemoryRemediationStore, RemediationStoreConflictError } from './remediationStore.js';
import { ALL_TENANTS } from '../lib/tenancy.js';

const future = '2099-01-01T00:00:00.000Z';

function exception(id, overrides = {}) {
  return {
    id,
    tenantId: 'default',
    cve: 'CVE-2023-45853',
    repository: 'ssi-images/onboarded/nginx',
    package: 'zlib1g',
    digest: null,
    reasonCode: 'no_fix_available',
    justification: 'Debian 12 will not fix this; minizip is not linked.',
    status: 'Requested',
    expiresAt: future,
    requestedBy: 'alex.morgan',
    decidedBy: null,
    history: [],
    createdAt: '2026-10-14T10:00:00.000Z',
    updatedAt: '2026-10-14T10:00:00.000Z',
    ...overrides,
  };
}

const audit = (resourceId) => ({
  id: resourceId,
  eventType: 'exception.requested',
  summary: 'x',
  metadata: {},
});

describe('risk acceptance persistence — memory', () => {
  it('generates EXC ids, stores newest first and writes the audit event', async () => {
    const store = new MemoryRemediationStore();
    expect(await store.nextExceptionId()).toBe('EXC-0001');
    expect(await store.nextExceptionId()).toBe('EXC-0002');
    await store.createException(exception('EXC-0001'), audit('EXC-0001'), ALL_TENANTS);
    await store.createException(
      exception('EXC-0002', { cve: 'CVE-2023-6879', package: 'libaom3' }),
      audit('EXC-0002'), ALL_TENANTS,
    );
    expect((await store.listExceptions(ALL_TENANTS)).map((item) => item.id)).toEqual(['EXC-0002', 'EXC-0001']);
    expect((await store.getException('EXC-0001', ALL_TENANTS)).rowVersion).toBe(1);
    expect(await store.getException('EXC-9999', ALL_TENANTS)).toBeNull();
    expect((await store.listAuditEvents({}, ALL_TENANTS)).length).toBe(2);
  });

  it('rejects a second open exception for an overlapping scope', async () => {
    const store = new MemoryRemediationStore();
    await store.createException(exception('EXC-0001', { package: null }), audit('EXC-0001'), ALL_TENANTS);
    await expect(store.createException(exception('EXC-0002'), audit('EXC-0002'), ALL_TENANTS)).rejects.toThrow(
      RemediationStoreConflictError,
    );
  });

  it('allows a new request once the previous one is closed or expired', async () => {
    const store = new MemoryRemediationStore();
    await store.createException(exception('EXC-0001', { status: 'Rejected' }), audit('EXC-0001'), ALL_TENANTS);
    await store.createException(
      exception('EXC-0002', { status: 'Approved', expiresAt: '2020-01-01T00:00:00.000Z' }),
      audit('EXC-0002'), ALL_TENANTS,
    );
    await expect(
      store.createException(exception('EXC-0003'), audit('EXC-0003'), ALL_TENANTS),
    ).resolves.toMatchObject({
      id: 'EXC-0003',
    });
  });

  it('uses optimistic locking on update', async () => {
    const store = new MemoryRemediationStore();
    const created = await store.createException(exception('EXC-0001'), audit('EXC-0001'), ALL_TENANTS);
    const updated = await store.updateException(
      { ...created, status: 'Approved', decidedBy: 'sam.lee' },
      audit('u1'), ALL_TENANTS,
    );
    expect(updated).toMatchObject({ status: 'Approved', rowVersion: 2 });
    await expect(
      store.updateException({ ...created, status: 'Rejected' }, audit('u2'), ALL_TENANTS),
    ).rejects.toThrow(/changed while/);
  });
});
