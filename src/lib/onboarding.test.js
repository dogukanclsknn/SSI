import { describe, expect, it } from 'vitest';
import {
  ONBOARDING_HANDOFF_CONTRACT,
  ONBOARDING_RECEIPT_CONTRACT,
  ONBOARDING_STATES,
  OnboardingValidationError,
  applyImportReceipt,
  buildOnboardingRequest,
  cancelOnboardingRequest,
  isImportReceiptReplay,
  OPEN_ONBOARDING_STATES,
  buildOnboardingWorkerHandoff,
  normalizeRegistryHost,
  parseAllowedRegistries,
  parseImageReference,
} from './onboarding.js';

const target = { registry: 'registry.example.com', project: 'ssi-images', repositoryPrefix: 'onboarded' };

describe('parseImageReference', () => {
  it('registry + path + tag ayrıştırır', () => {
    expect(parseImageReference('ghcr.io/org/app:1.2.3')).toMatchObject({
      registry: 'ghcr.io',
      repositoryPath: 'org/app',
      name: 'app',
      tag: '1.2.3',
      digest: '',
      pinnedByDigest: false,
    });
  });

  it('registry yoksa docker.io varsayar, tag yoksa latest', () => {
    expect(parseImageReference('nginx')).toMatchObject({ registry: 'docker.io', name: 'nginx', tag: 'latest' });
    expect(parseImageReference('library/nginx:1.27')).toMatchObject({ registry: 'docker.io', name: 'nginx', tag: '1.27' });
  });

  it('digest ile pinlenen referansı ayrıştırır', () => {
    const d = 'sha256:' + 'a'.repeat(64);
    expect(parseImageReference(`registry.example.com/team/api@${d}`)).toMatchObject({
      registry: 'registry.example.com',
      name: 'api',
      digest: d,
      pinnedByDigest: true,
      tag: '',
    });
  });

  it('geçersiz girdileri reddeder', () => {
    expect(() => parseImageReference('')).toThrow(OnboardingValidationError);
    expect(() => parseImageReference('nginx with space')).toThrow(OnboardingValidationError);
    expect(() => parseImageReference('repo@sha256:zzz')).toThrow(OnboardingValidationError);
    expect(() => parseImageReference('repo:bad tag')).toThrow(OnboardingValidationError);
  });
});

describe('buildOnboardingRequest', () => {
  it('karantina prefix altında hedef türetir', () => {
    const req = buildOnboardingRequest({
      id: 'ONB-0001',
      sourceReference: 'docker.io/library/nginx:1.27',
      target,
      requestedBy: 'alex.morgan',
      createdAt: '2026-09-03T08:00:00.000Z',
    });
    expect(req).toMatchObject({
      id: 'ONB-0001',
      status: ONBOARDING_STATES.REQUESTED,
      requestedBy: 'alex.morgan',
    });
    expect(req.target).toMatchObject({
      repository: 'onboarded/nginx',
      tag: '1.27',
      tagReference: 'registry.example.com/ssi-images/onboarded/nginx:1.27',
      quarantine: true,
    });
  });

  it('latest veya tagsiz kaynakta mutable tag yerine zaman damgalı tag türetir', () => {
    const req = buildOnboardingRequest({
      id: 'ONB-0002',
      sourceReference: 'nginx',
      target,
      createdAt: '2026-09-03T08:09:10.000Z',
    });
    expect(req.target.tag).toBe('onboard-20260903080910');
    expect(req.target.tag).not.toBe('latest');
  });

  it('hedef registry/proje yoksa reddeder', () => {
    expect(() => buildOnboardingRequest({ id: 'ONB-0003', sourceReference: 'nginx:1', target: {} })).toThrow(
      OnboardingValidationError,
    );
  });
});

describe('buildOnboardingWorkerHandoff', () => {
  const req = buildOnboardingRequest({ id: 'ONB-0001', sourceReference: 'ghcr.io/org/app:1.0', target });

  it('credential-free, kimlik bilgisi içermeyen handoff üretir', () => {
    const handoff = buildOnboardingWorkerHandoff(req);
    expect(handoff.contractVersion).toBe(ONBOARDING_HANDOFF_CONTRACT);
    expect(handoff.requestId).toBe('ONB-0001');
    expect(handoff.constraints).toMatchObject({ credentialMaterialIncluded: false, overwriteExistingTag: false, quarantine: true });
    const serialized = JSON.stringify(handoff).toLowerCase();
    expect(serialized).not.toContain('password');
    expect(serialized).not.toContain('secret');
    expect(serialized).not.toContain('token');
  });

  it('Requested olmayan istek için handoff üretmez', () => {
    expect(() => buildOnboardingWorkerHandoff({ ...req, status: ONBOARDING_STATES.IMPORTED })).toThrow(
      OnboardingValidationError,
    );
  });
});

describe('applyImportReceipt', () => {
  const req = buildOnboardingRequest({ id: 'ONB-0001', sourceReference: 'ghcr.io/org/app:1.0', target });
  const importedDigest = 'sha256:' + 'b'.repeat(64);

  it('başarılı import receipt isteği Imported yapar', () => {
    const updated = applyImportReceipt(req, {
      contractVersion: ONBOARDING_RECEIPT_CONTRACT,
      requestId: 'ONB-0001',
      status: 'imported',
      importedDigest,
      targetReference: req.target.tagReference,
      workerId: 'LinuxAgent1@host',
      scanSummary: { critical: 2, high: 3, medium: 5, low: 1, unknown: 0 },
    }, { acceptedAt: '2026-09-03T09:00:00.000Z' });

    expect(updated.status).toBe(ONBOARDING_STATES.IMPORTED);
    expect(updated.importedDigest).toBe(importedDigest);
    expect(updated.scanSummary).toEqual({ critical: 2, high: 3, medium: 5, low: 1, unknown: 0 });
    expect(updated.importedAt).toBe('2026-09-03T09:00:00.000Z');
  });

  it('failed receipt isteği Failed yapar ve hatayı taşır', () => {
    const updated = applyImportReceipt(req, {
      contractVersion: ONBOARDING_RECEIPT_CONTRACT,
      requestId: 'ONB-0001',
      status: 'failed',
      error: 'source registry unreachable',
      workerId: 'LinuxAgent1@host',
    });
    expect(updated.status).toBe(ONBOARDING_STATES.FAILED);
    expect(updated.error).toBe('source registry unreachable');
  });

  it('sözleşme/kimlik/digest uyuşmazlıklarını reddeder', () => {
    expect(() => applyImportReceipt(req, { contractVersion: 'x', requestId: 'ONB-0001', status: 'imported' })).toThrow();
    expect(() =>
      applyImportReceipt(req, { contractVersion: ONBOARDING_RECEIPT_CONTRACT, requestId: 'OTHER', status: 'imported' }),
    ).toThrow();
    expect(() =>
      applyImportReceipt(req, {
        contractVersion: ONBOARDING_RECEIPT_CONTRACT,
        requestId: 'ONB-0001',
        status: 'imported',
        importedDigest: 'not-a-digest',
        targetReference: req.target.tagReference,
      }),
    ).toThrow();
  });
});

describe('intake registry allowlist (ONBOARD_ALLOWED_REGISTRIES)', () => {
  const target = { registry: 'harbor.example.com', project: 'ssi', repositoryPrefix: 'onboarded' };

  it('parses and normalises the configured list', () => {
    expect(parseAllowedRegistries(' docker.io, GHCR.io ,, index.docker.io ')).toEqual(['docker.io', 'ghcr.io']);
    expect(parseAllowedRegistries('')).toEqual([]);
    expect(normalizeRegistryHost('registry-1.docker.io')).toBe('docker.io');
  });

  it('accepts an image from an allowed registry, including Docker Hub short names', () => {
    const allowedRegistries = parseAllowedRegistries('docker.io,ghcr.io');
    expect(
      buildOnboardingRequest({ id: 'ONB-1', sourceReference: 'nginx:1.27', target, allowedRegistries }).source.registry,
    ).toBe('docker.io');
    expect(() =>
      buildOnboardingRequest({ id: 'ONB-2', sourceReference: 'ghcr.io/org/app:1', target, allowedRegistries }),
    ).not.toThrow();
  });

  it('rejects an image from a registry outside the allowlist', () => {
    expect(() =>
      buildOnboardingRequest({
        id: 'ONB-3',
        sourceReference: 'evil.example.net/x/app:1',
        target,
        allowedRegistries: ['docker.io'],
      }),
    ).toThrow(/not an approved intake source/);
  });

  it('applies no restriction when the list is empty', () => {
    expect(() =>
      buildOnboardingRequest({ id: 'ONB-4', sourceReference: 'quay.io/org/app:1', target, allowedRegistries: [] }),
    ).not.toThrow();
  });
});

describe('cancelOnboardingRequest (a request no worker will finish)', () => {
  const req = buildOnboardingRequest({ id: 'ONB-0002', sourceReference: 'docker.io/library/nginx:1.27', target });
  const reason = 'Duplicate request; ONB-0001 covers this image.';
  const receipt = (overrides = {}) => ({
    contractVersion: ONBOARDING_RECEIPT_CONTRACT,
    requestId: 'ONB-0002',
    status: 'imported',
    importedDigest: 'sha256:' + 'c'.repeat(64),
    targetReference: req.target.tagReference,
    workerId: 'LinuxAgent1@host',
    ...overrides,
  });

  it('closes a Requested or Importing request and keeps who, why and when', () => {
    for (const status of OPEN_ONBOARDING_STATES) {
      const cancelled = cancelOnboardingRequest({ ...req, status }, { actorId: 'alex.morgan', reason, cancelledAt: '2026-11-11T14:00:00.000Z' });
      expect(cancelled).toMatchObject({
        status: ONBOARDING_STATES.CANCELLED,
        updatedAt: '2026-11-11T14:00:00.000Z',
        cancellation: { cancelledBy: 'alex.morgan', reason, cancelledAt: '2026-11-11T14:00:00.000Z', previousStatus: status },
      });
    }
  });

  it('refuses finished requests, a missing identity and an invalid reason', () => {
    for (const status of [ONBOARDING_STATES.IMPORTED, ONBOARDING_STATES.FAILED, ONBOARDING_STATES.CANCELLED]) {
      expect(() => cancelOnboardingRequest({ ...req, status }, { actorId: 'a', reason })).toThrow(/Only a Requested or Importing/);
    }
    expect(() => cancelOnboardingRequest(req, { actorId: '', reason })).toThrow(/signed-in identity/);
    expect(() => cancelOnboardingRequest(req, { actorId: 'a', reason: 'too short' })).toThrow(/10-1000 characters/);
    expect(() => cancelOnboardingRequest(req, { actorId: 'a', reason: 'line one\nline two is here' })).toThrow(/single line/);
    expect(() => cancelOnboardingRequest(req, { actorId: 'a', reason: 42 })).toThrow(/must be text/);
  });

  it('a cancelled request is never handed to a worker', () => {
    const cancelled = cancelOnboardingRequest(req, { actorId: 'a', reason });
    expect(() => buildOnboardingWorkerHandoff(cancelled)).toThrow(OnboardingValidationError);
  });

  it('records a late receipt of a worker that had already started, without reopening', () => {
    const cancelled = cancelOnboardingRequest({ ...req, status: 'Importing' }, { actorId: 'a', reason });
    const late = applyImportReceipt(cancelled, receipt(), { acceptedAt: '2026-11-11T14:05:00.000Z' });
    expect(late.status).toBe(ONBOARDING_STATES.CANCELLED);
    expect(late.importAfterCancellation).toMatchObject({
      status: 'imported',
      importedDigest: 'sha256:' + 'c'.repeat(64),
      targetReference: req.target.tagReference,
      recordedAt: '2026-11-11T14:05:00.000Z',
    });
    expect(isImportReceiptReplay(late, receipt())).toBe(true);
    expect(() => applyImportReceipt(late, receipt({ importedDigest: 'sha256:' + 'd'.repeat(64) }))).toThrow(/already recorded/);
    expect(() => applyImportReceipt(cancelled, receipt({ targetReference: 'harbor/x:y' }))).toThrow(/target reference/);
  });

  it('recognises a retried receipt of a finished request as a replay', () => {
    const imported = applyImportReceipt(req, receipt());
    expect(isImportReceiptReplay(imported, receipt())).toBe(true);
    expect(isImportReceiptReplay(imported, receipt({ importedDigest: 'sha256:' + 'd'.repeat(64) }))).toBe(false);
    expect(isImportReceiptReplay(req, receipt())).toBe(false);
  });
});
