import { describe, expect, it } from 'vitest';
import { applyImageInspection } from '../lib/imageInspection.js';
import { ALL_TENANTS } from '../lib/tenancy.js';
import { MemoryRemediationStore } from './remediationStore.js';

const REFERENCE = `ssi-images/onboarded/nginx@sha256:${'a'.repeat(64)}`;
const record = (generatedAt, letter) => ({
  reference: REFERENCE,
  digest: `sha256:${'a'.repeat(64)}`,
  generatedAt,
  evidenceDigest: `sha256:${letter.repeat(64)}`,
  os: 'alpine 3.22.2',
  packages: [{ name: 'curl', arch: 'x86_64', version: '8.23.0-r0' }],
});
const audit = (summary) => ({ id: summary, eventType: 'image.inspection.accepted', summary, tenantId: 'default' });

describe('image inspections in the memory store', () => {
  it('stores an inspection with its audit event and reads it back by scan reference', async () => {
    const store = new MemoryRemediationStore();
    const saved = await store.saveImageInspection(record('2026-11-11T10:00:00.000Z', 'b'), applyImageInspection, audit('first'));
    expect(saved.changed).toBe(true);
    const found = await store.getImageInspections([REFERENCE, 'ssi-images/other@sha256:' + 'c'.repeat(64)]);
    expect([...found.keys()]).toEqual([REFERENCE]);
    expect(found.get(REFERENCE).packages).toHaveLength(1);
    expect((await store.listAuditEvents({}, ALL_TENANTS)).map((event) => event.summary)).toEqual(['first']);
  });

  it('keeps a replay silent and refuses an older inspection without an audit event', async () => {
    const store = new MemoryRemediationStore();
    await store.saveImageInspection(record('2026-11-11T10:00:00.000Z', 'b'), applyImageInspection, audit('first'));
    const replay = await store.saveImageInspection(record('2026-11-11T10:00:00.000Z', 'b'), applyImageInspection, audit('replay'));
    expect(replay.changed).toBe(false);
    await expect(
      store.saveImageInspection(record('2026-11-11T09:00:00.000Z', 'd'), applyImageInspection, audit('older')),
    ).rejects.toThrow(/newer inspection/);
    expect((await store.listAuditEvents({}, ALL_TENANTS)).map((event) => event.summary)).toEqual(['first']);
  });

  it('returns copies, so a caller cannot change the stored record', async () => {
    const store = new MemoryRemediationStore();
    await store.saveImageInspection(record('2026-11-11T10:00:00.000Z', 'b'), applyImageInspection, null);
    const first = await store.getImageInspections([REFERENCE]);
    first.get(REFERENCE).packages.length = 0;
    expect((await store.getImageInspections([REFERENCE])).get(REFERENCE).packages).toHaveLength(1);
  });
});
