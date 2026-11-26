import { describe, expect, it } from 'vitest';
import {
  annotateOwnership,
  assertDistinctHarborAreas,
  isVisibleImage,
  isVisibleScanReport,
  ownerOfRepository,
  teamHarborAreas,
  teamTargets,
} from './tenantInventory.js';
import { ALL_TENANTS, tenantScope } from './tenancy.js';
import { buildOnboardingRequest } from './onboarding.js';

const platform = {
  onboarding: { registry: 'harbor.example', project: 'ssi-images', repositoryPrefix: 'onboarded' },
  publish: { registry: 'harbor.example', project: 'ssi-images', repositoryPrefix: 'approved' },
};
const team = (id, harbor = {}, displayName = id) => ({ id, displayName, status: 'active', harbor });
const teams = [team('default', {}, 'Default'), team('payments', {}, 'Payments'), team('mobile', { project: 'mobile-repo' }, 'Mobile')];
const areas = teamHarborAreas(teams, platform);

describe('team Harbor targets', () => {
  it("keeps today's folders for the default team", () => {
    expect(teamTargets(team('default'), platform)).toEqual(platform);
  });

  it('gives a team in the shared project its own folders (option A)', () => {
    expect(teamTargets(team('payments'), platform)).toEqual({
      onboarding: { registry: 'harbor.example', project: 'ssi-images', repositoryPrefix: 'onboarded/payments' },
      publish: { registry: 'harbor.example', project: 'ssi-images', repositoryPrefix: 'approved/payments' },
    });
  });

  it('keeps the plain folder names in a project of its own (option B)', () => {
    expect(teamTargets(team('mobile', { project: 'mobile-repo' }), platform).publish).toEqual({
      registry: 'harbor.example',
      project: 'mobile-repo',
      repositoryPrefix: 'approved',
    });
  });

  it('uses the folders a team configures', () => {
    const targets = teamTargets(team('payments', { onboardPrefix: '/quarantine/pay/', approvedPrefix: 'release/pay' }), platform);
    expect(targets.onboarding.repositoryPrefix).toBe('quarantine/pay');
    expect(targets.publish.repositoryPrefix).toBe('release/pay');
  });
});

describe('ownerOfRepository', () => {
  it.each([
    ['ssi-images', 'onboarded/nginx', 'default', 'onboarded'],
    ['ssi-images', 'approved/ssi-remediation-test', 'default', 'approved'],
    ['ssi-images', 'onboarded/payments/redis', 'payments', 'onboarded'],
    ['ssi-images', 'approved/payments/api', 'payments', 'approved'],
    ['ssi-images', 'approved/payments', 'payments', 'approved'],
    ['mobile-repo', 'approved/app', 'mobile', 'approved'],
    ['SSI-IMAGES', 'Onboarded/Payments/redis', 'payments', 'onboarded'],
  ])('%s/%s belongs to %s (%s)', (project, repository, tenantId, tenantArea) => {
    expect(ownerOfRepository({ project, repository }, areas)).toMatchObject({ tenantId, tenantArea });
  });

  it('does not match a folder by name prefix alone', () => {
    // "approved/paymentsx" is not inside "approved/payments": it is the default team's.
    expect(ownerOfRepository({ project: 'ssi-images', repository: 'approved/paymentsx/api' }, areas)).toMatchObject({
      tenantId: 'default',
      tenantArea: 'approved',
    });
  });

  it("leaves an image outside every team's folders with the default team", () => {
    expect(ownerOfRepository({ project: 'ssi-images', repository: 'copa-poc/nginx' }, areas)).toEqual({
      tenantId: 'default',
      tenantName: 'Default',
      tenantArea: null,
    });
    expect(ownerOfRepository({ project: 'other-project', repository: 'approved/x' }, areas).tenantId).toBe('default');
  });

  it('annotates items with their owner', () => {
    const [image] = annotateOwnership([{ id: 'x', project: 'ssi-images', repository: 'approved/payments/api' }], areas, (item) => item);
    expect(image).toEqual({
      id: 'x',
      project: 'ssi-images',
      repository: 'approved/payments/api',
      tenantId: 'payments',
      tenantName: 'Payments',
      tenantArea: 'approved',
    });
  });
});

describe('folder conflicts', () => {
  it('refuses two teams in the same folder', () => {
    const clash = teamHarborAreas([...teams, team('cards', { approvedPrefix: 'approved/payments' })], platform);
    expect(() => assertDistinctHarborAreas(clash)).toThrow(/already used by team payments/);
  });

  it("refuses a team whose onboard and approved folders are the same", () => {
    const same = teamHarborAreas([team('cards', { onboardPrefix: 'cards', approvedPrefix: 'cards' })], platform);
    expect(() => assertDistinctHarborAreas(same)).toThrow(/must differ/);
  });

  it('allows nested folders of different teams', () => {
    expect(() => assertDistinctHarborAreas(areas)).not.toThrow();
  });
});

describe('visibility', () => {
  const images = annotateOwnership(
    [
      { id: 'def-onb', project: 'ssi-images', repository: 'onboarded/nginx' },
      { id: 'def-app', project: 'ssi-images', repository: 'approved/ssi-remediation-test' },
      { id: 'pay-onb', project: 'ssi-images', repository: 'onboarded/payments/redis' },
      { id: 'pay-app', project: 'ssi-images', repository: 'approved/payments/api' },
      { id: 'loose', project: 'ssi-images', repository: 'copa-poc/nginx' },
    ],
    areas,
    (item) => item,
  );
  const visible = (scope) => images.filter((image) => isVisibleImage(image, scope)).map((image) => image.id);

  it('shows a team its own images and the shared catalog of published images', () => {
    expect(visible(tenantScope('payments'))).toEqual(['def-app', 'pay-onb', 'pay-app']);
    expect(visible(tenantScope('default'))).toEqual(['def-onb', 'def-app', 'pay-app', 'loose']);
    expect(visible(ALL_TENANTS)).toHaveLength(5);
  });

  it('keeps scan results inside the team', () => {
    expect(images.filter((report) => isVisibleScanReport(report, tenantScope('payments'))).map((item) => item.id)).toEqual([
      'pay-onb',
      'pay-app',
    ]);
  });
});

describe('onboarding into a team folder', () => {
  it('accepts a nested quarantine folder and keeps rejecting invalid ones', () => {
    const request = buildOnboardingRequest({
      id: 'ONB-0001',
      sourceReference: 'docker.io/library/nginx:1.27',
      target: teamTargets(team('payments'), platform).onboarding,
      requestedBy: 'ayse',
    });
    expect(request.target.repository).toBe('onboarded/payments/nginx');
    expect(request.target.tagReference).toMatch(/^harbor\.example\/ssi-images\/onboarded\/payments\/nginx:/);
    for (const repositoryPrefix of ['onboarded/', '/onboarded', 'onboarded//payments', '../approved', 'on boarded']) {
      expect(() =>
        buildOnboardingRequest({
          id: 'ONB-0002',
          sourceReference: 'docker.io/library/nginx:1.27',
          target: { registry: 'harbor.example', project: 'ssi-images', repositoryPrefix },
          requestedBy: 'ayse',
        }),
      ).toThrow(/Invalid quarantine prefix/);
    }
  });
});
