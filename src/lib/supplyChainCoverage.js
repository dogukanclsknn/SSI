// SSI — Supply-chain coverage of the production (approved/) image set.
//
// Harbor's artifact listing does not tell SSI whether an image is signed or has an
// SBOM. SSI's own source of truth is the VERIFIED supply-chain evidence attached to
// RM-EXEC jobs (Cosign signature, Syft SBOM, provenance — see supplyChainEvidence.js),
// bound to the job's immutable output digest. This module marks inventory images whose
// full digest carries such evidence and computes the production gate coverage over the
// approved/ boundary of the publish policy. Pure: no I/O.

import { isTechnicalArtifact } from './harbor.js';

export { isTechnicalArtifact };

const sha256Pattern = /^sha256:[a-f0-9]{64}$/;

function normalizeDigest(value) {
  return String(value || '').trim().toLowerCase();
}

// What the verified SBOM evidence says about the SBOM attached to the image (its format,
// component count and digest), or null. The component list itself stays in Harbor as the
// signed CycloneDX attestation; SSI keeps the summary the signing worker verified.
function sbomSummaryOf(supplyChain) {
  const sbom = supplyChain?.details?.sbom;
  if (supplyChain?.sbom !== true || !sbom?.present || !Number.isInteger(sbom.componentCount)) return null;
  return {
    format: String(sbom.format || ''),
    componentCount: sbom.componentCount,
    sbomDigest: String(sbom.sbomDigest || ''),
    tool: String(sbom.tool || ''),
    verifiedAt: String(supplyChain.verifiedAt || ''),
  };
}

function evidenceByDigest(jobs) {
  const index = new Map();
  for (const job of Array.isArray(jobs) ? jobs : []) {
    const supplyChain = job?.supplyChain;
    const digest = normalizeDigest(job?.patchedImageDigest || supplyChain?.outputDigest);
    if (!supplyChain || !sha256Pattern.test(digest)) continue;
    const current = index.get(digest) || { signature: false, sbom: false, provenance: false, sbomSummary: null };
    index.set(digest, {
      signature: current.signature || supplyChain.signature === true,
      sbom: current.sbom || supplyChain.sbom === true,
      provenance: current.provenance || supplyChain.provenance === true,
      sbomSummary: current.sbomSummary || sbomSummaryOf(supplyChain),
    });
  }
  return index;
}

// Output digests withdrawn after publish (src/lib/publishLifecycle.js) → withdrawal record.
function withdrawalsByDigest(jobs) {
  const index = new Map();
  for (const job of Array.isArray(jobs) ? jobs : []) {
    const withdrawal = job?.publishWithdrawal;
    const digest = normalizeDigest(withdrawal?.digest);
    if (withdrawal && sha256Pattern.test(digest) && !index.has(digest)) index.set(digest, withdrawal);
  }
  return index;
}

// Returns new image objects: signature/sbom/provenance become true when verified
// evidence exists for the image's full digest (existing true flags are kept), `sbomSummary`
// carries the verified SBOM's format, component count and digest (or null),
// `approvedScope` marks images inside the publish target boundary, and `withdrawn` carries
// the withdrawal record of an image that must no longer be used.
export function applySupplyChainEvidence(images, jobs, { project = '', repositoryPrefix = '' } = {}) {
  const evidence = evidenceByDigest(jobs);
  const withdrawals = withdrawalsByDigest(jobs);
  const prefix = repositoryPrefix ? `${String(repositoryPrefix).replace(/\/+$/, '')}/` : '';
  return (Array.isArray(images) ? images : []).map((image) => {
    const found = evidence.get(normalizeDigest(image.fullDigest));
    const repository = String(image.repository || '');
    return {
      ...image,
      signature: image.signature === true || Boolean(found?.signature),
      sbom: image.sbom === true || Boolean(found?.sbom),
      provenance: image.provenance === true || Boolean(found?.provenance),
      sbomSummary: found?.sbomSummary || image.sbomSummary || null,
      withdrawn: withdrawals.get(normalizeDigest(image.fullDigest)) || null,
      // Production boundary: deployable images under approved/ of the target project.
      // Cosign accessories and untagged manifests are never counted.
      approvedScope:
        Boolean(prefix) && image.project === project && repository.startsWith(prefix) && !isTechnicalArtifact(image),
    };
  });
}

// The approved catalog: images inside a publish boundary (the platform's approved/ area, or a
// team's approved folder when multi-tenancy is on) that were not withdrawn, Cosign accessories
// and untagged manifests excluded. Unrelated to the scan verdict `image.status` ("Approved"
// there only means no critical or high finding, which an onboarded image can have too).
export function isApprovedCatalogImage(image) {
  return (
    (image?.approvedScope === true || image?.tenantArea === 'approved') &&
    !image?.withdrawn &&
    !isTechnicalArtifact(image)
  );
}

// Production gate: share of approved images that are both signed and have an SBOM. A
// withdrawn image is never covered, and `withdrawn` counts the ones still present under
// approved/ (they should be removed from the registry).
export function supplyChainCoverage(images) {
  const scoped = (Array.isArray(images) ? images : []).filter((image) => image.approvedScope === true);
  const covered = scoped.filter((image) => !image.withdrawn && image.signature === true && image.sbom === true).length;
  return {
    total: scoped.length,
    covered,
    withdrawn: scoped.filter((image) => Boolean(image.withdrawn)).length,
    percent: scoped.length > 0 ? Math.round((covered / scoped.length) * 100) : null,
  };
}
