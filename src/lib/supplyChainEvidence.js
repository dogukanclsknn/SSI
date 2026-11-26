import { createHash } from 'node:crypto';

// SSI — Tedarik zinciri kanıtı (imza + SBOM + provenance) doğrulaması.
//
// Faz 5 / Tema F: yalnızca doğrulanmış (Verified) bir RM-EXEC değil, aynı zamanda
// İMZALANMIŞ + SBOM'lu + provenance'lı bir imaj yayınlarız. İzole publish worker'ı
// approved/ digest'ini açık kaynak araçlarla imzalar (Sigstore **Cosign**), SBOM üretir
// (Anchore **Syft**, CycloneDX) ve bir provenance attestation'ı ekler; sonra bu kanıtı
// HMAC ile imzalı bir receipt olarak SSI'ya gönderir (mevcut worker-handoff deseni).
//
// TASARIM — ESNEK ve TOOL-AGNOSTİK: SSI yalnızca "imzalandı mı / doğrulandı mı" boolean'ı
// ve digest bağlarıyla ilgilenir. İmza modeli key-based Cosign'dan yarın KMS ya da keyless'a
// geçse de (worker değişir) SSI mantığı değişmez. `verifier` alanı kanıtın NASIL doğrulandığını
// taşır; ileride 'ssi-cosign' (SSI'nın kendi doğrulaması) gibi modlar eklenebilir.
//
// publishPolicy.evaluatePublishPolicy zaten `job.supplyChain.{signature,sbom,provenance}`
// boolean'larını okur — bu modül o boolean'ları + UI için zengin detayı üretir.

const sha256Pattern = /^sha256:[a-f0-9]{64}$/i;

export const SUPPLY_CHAIN_EVIDENCE_CONTRACT_VERSION = 'ssi.supply-chain/v1alpha1';
export const SBOM_FORMATS = { CYCLONEDX: 'cyclonedx-json', SPDX: 'spdx-json' };

export class SupplyChainEvidenceValidationError extends Error {
  constructor(message, statusCode = 422) {
    super(message);
    this.name = 'SupplyChainEvidenceValidationError';
    this.statusCode = statusCode;
  }
}

function assert(condition, message) {
  if (!condition) {
    throw new SupplyChainEvidenceValidationError(message);
  }
}

function asText(value) {
  return value == null ? '' : String(value).trim();
}

function normalizedDigest(value) {
  return asText(value).toLowerCase();
}

function isSha256(value) {
  return sha256Pattern.test(asText(value));
}

function asBoolean(value) {
  return value === true;
}

// İmza bloğu: worker approved/ digest'ini imzaladı ve public key ile doğruladı mı?
function normalizeSignature(value, expectedOutputDigest) {
  if (value == null) {
    return { present: false, signed: false, verified: false };
  }
  assert(typeof value === 'object' && !Array.isArray(value), 'signature must be an object.');

  const signed = asBoolean(value.signed);
  const verified = asBoolean(value.verified);
  const signatureDigest = normalizedDigest(value.signatureDigest);
  assert(!signatureDigest || isSha256(signatureDigest), 'signature.signatureDigest must be a sha256 digest.');

  // İmza mutlaka approved/ çıktı digest'i üzerinde olmalı (bağ kopmasın).
  const signedDigest = normalizedDigest(value.signedDigest || expectedOutputDigest);
  assert(
    !signed || signedDigest === expectedOutputDigest,
    'signature.signedDigest must match the approved output digest.',
  );

  return {
    present: true,
    signed,
    verified,
    ok: signed && verified,
    keyId: asText(value.keyId),
    signatureDigest,
    tool: asText(value.tool) || 'cosign',
    signedDigest,
  };
}

// SBOM bloğu: worker CycloneDX (ya da SPDX) SBOM üretti ve attestation olarak ekledi mi?
function normalizeSbom(value) {
  if (value == null) {
    return { present: false, ok: false };
  }
  assert(typeof value === 'object' && !Array.isArray(value), 'sbom must be an object.');

  const format = asText(value.format).toLowerCase() || SBOM_FORMATS.CYCLONEDX;
  assert(
    format === SBOM_FORMATS.CYCLONEDX || format === SBOM_FORMATS.SPDX,
    'sbom.format must be cyclonedx-json or spdx-json.',
  );
  const sbomDigest = normalizedDigest(value.sbomDigest);
  assert(isSha256(sbomDigest), 'sbom.sbomDigest must be a sha256 digest.');
  const attestationDigest = normalizedDigest(value.attestationDigest);
  assert(!attestationDigest || isSha256(attestationDigest), 'sbom.attestationDigest must be a sha256 digest.');

  const componentCount = Number(value.componentCount);
  assert(
    Number.isInteger(componentCount) && componentCount >= 0,
    'sbom.componentCount must be a non-negative integer.',
  );
  const verified = asBoolean(value.verified);

  return {
    present: true,
    ok: verified,
    verified,
    format,
    sbomDigest,
    attestationDigest,
    componentCount,
    tool: asText(value.tool) || 'syft',
  };
}

// Provenance bloğu: attestation, kaynak (dış imaj) digest'ine kadar izlenebilirlik sağlar.
function normalizeProvenance(value, expectedOutputDigest) {
  if (value == null) {
    return { present: false, ok: false };
  }
  assert(typeof value === 'object' && !Array.isArray(value), 'provenance must be an object.');

  const attestationDigest = normalizedDigest(value.attestationDigest);
  assert(isSha256(attestationDigest), 'provenance.attestationDigest must be a sha256 digest.');
  const sourceDigest = normalizedDigest(value.sourceDigest);
  assert(!sourceDigest || isSha256(sourceDigest), 'provenance.sourceDigest must be a sha256 digest.');
  const subjectDigest = normalizedDigest(value.subjectDigest || expectedOutputDigest);
  assert(
    subjectDigest === expectedOutputDigest,
    'provenance.subjectDigest must match the approved output digest.',
  );
  const verified = asBoolean(value.verified);

  return {
    present: true,
    ok: verified,
    verified,
    attestationDigest,
    sourceDigest,
    subjectDigest,
    buildRef: asText(value.buildRef),
    predicateType: asText(value.predicateType) || 'https://slsa.dev/provenance/v1',
  };
}

// Kanıt gövdesini doğrular ve job'a iliştirilecek `supplyChain` nesnesini döner.
// publishPolicy'nin okuduğu boolean'lar: supplyChain.signature / .sbom / .provenance.
export function validateSupplyChainEvidence(evidence, { expectedOutputDigest, rawContent } = {}) {
  assert(
    evidence && typeof evidence === 'object' && !Array.isArray(evidence),
    'Supply-chain evidence must be a JSON object.',
  );

  const outputDigest = normalizedDigest(expectedOutputDigest);
  assert(isSha256(outputDigest), 'A valid immutable approved output digest is required.');

  const evidenceOutputDigest = normalizedDigest(evidence.outputDigest);
  assert(
    evidenceOutputDigest === outputDigest,
    'Supply-chain evidence outputDigest does not match the approved output digest.',
  );

  const signature = normalizeSignature(evidence.signature, outputDigest);
  const sbom = normalizeSbom(evidence.sbom);
  const provenance = normalizeProvenance(evidence.provenance, outputDigest);

  const verifier = asText(evidence.verifier) || 'worker-cosign';
  const verifiedAt = asText(evidence.verifiedAt) || new Date().toISOString();

  const supplyChain = {
    // publishPolicy bu üç boolean'ı okur:
    signature: signature.ok === true,
    sbom: sbom.ok === true,
    provenance: provenance.ok === true,
    verifier,
    verifiedAt,
    outputDigest,
    contractVersion: SUPPLY_CHAIN_EVIDENCE_CONTRACT_VERSION,
    details: { signature, sbom, provenance },
  };

  if (typeof rawContent === 'string' && rawContent.length > 0) {
    // İçerik digest'i (izlenebilirlik/audit için); zorunlu değil.
    supplyChain.contentDigest = `sha256:${createHash('sha256').update(rawContent, 'utf8').digest('hex')}`;
  }

  return { supplyChain };
}
