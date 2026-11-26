import { describe, expect, it } from 'vitest';
import { applySupplyChainEvidence, isApprovedCatalogImage, supplyChainCoverage } from './supplyChainCoverage.js';

const SIGNED = `sha256:${'a'.repeat(64)}`;
const UNSIGNED = `sha256:${'b'.repeat(64)}`;
const boundary = { project: 'ssi-images', repositoryPrefix: 'approved' };

const image = (repository, fullDigest, extra = {}) => ({
  id: `${repository}-${fullDigest.slice(7, 11)}`,
  project: 'ssi-images',
  repository,
  fullDigest,
  signature: false,
  sbom: false,
  provenance: false,
  ...extra,
});

const signedJob = {
  id: 'RM-EXEC-0001',
  patchedImageDigest: SIGNED,
  supplyChain: { signature: true, sbom: true, provenance: true },
};

describe('applySupplyChainEvidence', () => {
  it('marks images whose full digest carries verified evidence', () => {
    const [signed, unsigned] = applySupplyChainEvidence(
      [image('approved/nginx', SIGNED), image('approved/redis', UNSIGNED)],
      [signedJob],
      boundary,
    );
    expect(signed).toMatchObject({ signature: true, sbom: true, provenance: true, approvedScope: true });
    expect(unsigned).toMatchObject({ signature: false, sbom: false, approvedScope: true });
  });

  it('scopes the production boundary to the approved prefix of the target project', () => {
    const images = applySupplyChainEvidence(
      [
        image('onboarded/nginx', SIGNED),
        image('approved-old/nginx', SIGNED),
        image('approved/nginx', SIGNED, { project: 'other-project' }),
      ],
      [signedJob],
      boundary,
    );
    expect(images.map((item) => item.approvedScope)).toEqual([false, false, false]);
    expect(images[0].signature).toBe(true); // same digest, evidence still shown
  });

  it('carries the verified SBOM summary (format, component count, digest) onto the image', () => {
    const sbomDigest = `sha256:${'c'.repeat(64)}`;
    const verifiedJob = {
      ...signedJob,
      supplyChain: {
        ...signedJob.supplyChain,
        verifiedAt: '2026-11-16T21:25:00.000Z',
        details: {
          sbom: { present: true, ok: true, format: 'cyclonedx-json', componentCount: 1032, sbomDigest, tool: 'syft v1.20.0' },
        },
      },
    };
    const [signed, unsigned] = applySupplyChainEvidence(
      [image('approved/nginx', SIGNED), image('approved/redis', UNSIGNED)],
      [verifiedJob],
      boundary,
    );
    expect(signed.sbomSummary).toEqual({
      format: 'cyclonedx-json',
      componentCount: 1032,
      sbomDigest,
      tool: 'syft v1.20.0',
      verifiedAt: '2026-11-16T21:25:00.000Z',
    });
    expect(unsigned.sbomSummary).toBeNull();
    // Evidence whose SBOM did not verify gives no summary.
    const [unverified] = applySupplyChainEvidence(
      [image('approved/nginx', SIGNED)],
      [{ ...verifiedJob, supplyChain: { ...verifiedJob.supplyChain, sbom: false } }],
      boundary,
    );
    expect(unverified.sbomSummary).toBeNull();
  });

  it('ignores jobs without evidence or with a non-sha256 digest', () => {
    const [result] = applySupplyChainEvidence(
      [image('approved/nginx', SIGNED)],
      [{ patchedImageDigest: SIGNED }, { patchedImageDigest: 'latest', supplyChain: { signature: true, sbom: true } }],
      boundary,
    );
    expect(result).toMatchObject({ signature: false, sbom: false });
  });

  it('requires both signature and SBOM evidence to count as covered', () => {
    const images = applySupplyChainEvidence(
      [image('approved/nginx', SIGNED)],
      [{ patchedImageDigest: SIGNED, supplyChain: { signature: true, sbom: false } }],
      boundary,
    );
    expect(supplyChainCoverage(images)).toEqual({ total: 1, covered: 0, withdrawn: 0, percent: 0 });
  });
});

describe('supplyChainCoverage', () => {
  it('reports covered / total approved images', () => {
    const images = applySupplyChainEvidence(
      [image('approved/nginx', SIGNED), image('approved/redis', UNSIGNED), image('onboarded/x', UNSIGNED)],
      [signedJob],
      boundary,
    );
    expect(supplyChainCoverage(images)).toEqual({ total: 2, covered: 1, withdrawn: 0, percent: 50 });
  });

  it('has no percentage when there are no approved images', () => {
    expect(supplyChainCoverage([image('onboarded/x', UNSIGNED)])).toEqual({ total: 0, covered: 0, withdrawn: 0, percent: null });
  });
});

describe('technical artifacts', () => {
  it('never counts Cosign accessories or untagged manifests in the production boundary', () => {
    const accessory = image('approved/nginx', SIGNED, { version: `sha256-${'a'.repeat(64)}.att` });
    const signatureTag = image('approved/nginx', SIGNED, { version: `sha256-${'a'.repeat(64)}.sig` });
    const untagged = image('approved/nginx', UNSIGNED, { version: 'bbbbbbbbbbbb', digest: 'sha256:bbbbbbbbbbbb' });
    const real = image('approved/nginx', SIGNED, { version: 'verified-20261014-r1' });
    const images = applySupplyChainEvidence([accessory, signatureTag, untagged, real], [signedJob], boundary);
    expect(images.map((item) => item.approvedScope)).toEqual([false, false, false, true]);
    expect(supplyChainCoverage(images)).toEqual({ total: 1, covered: 1, withdrawn: 0, percent: 100 });
  });
});

describe('withdrawn images', () => {
  const withdrawnJob = {
    ...signedJob,
    publishWithdrawal: { digest: SIGNED, withdrawnBy: 'sam.lee', reason: 'Broken after publish.' },
  };

  it('marks a withdrawn image, never counts it as covered and reports it in the boundary', () => {
    const images = applySupplyChainEvidence(
      [image('approved/nginx', SIGNED), image('approved/redis', UNSIGNED)],
      [withdrawnJob],
      boundary,
    );
    expect(images[0]).toMatchObject({ signature: true, sbom: true, withdrawn: { withdrawnBy: 'sam.lee' } });
    expect(images[1].withdrawn).toBeNull();
    expect(supplyChainCoverage(images)).toEqual({ total: 2, covered: 0, withdrawn: 1, percent: 0 });
  });

  it('ignores a withdrawal record without a valid digest', () => {
    const [result] = applySupplyChainEvidence(
      [image('approved/nginx', SIGNED)],
      [{ ...signedJob, publishWithdrawal: { digest: 'latest' } }],
      boundary,
    );
    expect(result.withdrawn).toBeNull();
  });
});

describe('isApprovedCatalogImage (Dashboard catalog, App Builder bases)', () => {
  const withdrawnJob = { ...signedJob, publishWithdrawal: { digest: SIGNED, withdrawnBy: 'sam.lee', reason: 'Broken after publish.' } };

  it('counts only images in the approved area, never a clean onboarded image', () => {
    // A clean scan gives status "Approved" to any image; that is not the catalog.
    const onboarded = { ...image('onboarded/nginx', UNSIGNED), status: 'Approved' };
    const published = image('approved/nginx', SIGNED);
    const images = applySupplyChainEvidence([onboarded, published], [signedJob], boundary);
    expect(images.map(isApprovedCatalogImage)).toEqual([false, true]);
  });

  it('excludes withdrawn images and technical artifacts', () => {
    const accessory = image('approved/nginx', SIGNED, { version: `sha256-${'a'.repeat(64)}.att` });
    const images = applySupplyChainEvidence([image('approved/nginx', SIGNED), accessory], [withdrawnJob], boundary);
    expect(images.map(isApprovedCatalogImage)).toEqual([false, false]);
  });

  it('includes a team approved folder outside the platform boundary (multi-tenancy)', () => {
    const teamImage = { ...image('approved/api', UNSIGNED, { project: 'payments-repo' }), tenantArea: 'approved' };
    const [annotated] = applySupplyChainEvidence([teamImage], [], boundary);
    expect(annotated.approvedScope).toBe(false);
    expect(isApprovedCatalogImage(annotated)).toBe(true);
  });
});
