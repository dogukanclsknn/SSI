import { describe, expect, it } from 'vitest';
import {
  validateSupplyChainEvidence,
  SupplyChainEvidenceValidationError,
  SUPPLY_CHAIN_EVIDENCE_CONTRACT_VERSION,
} from './supplyChainEvidence.js';

const OUTPUT_DIGEST = `sha256:${'a'.repeat(64)}`;
const SOURCE_DIGEST = `sha256:${'b'.repeat(64)}`;
const SBOM_DIGEST = `sha256:${'c'.repeat(64)}`;
const SIG_DIGEST = `sha256:${'d'.repeat(64)}`;
const ATT_DIGEST = `sha256:${'e'.repeat(64)}`;

function fullEvidence() {
  return {
    contractVersion: SUPPLY_CHAIN_EVIDENCE_CONTRACT_VERSION,
    outputDigest: OUTPUT_DIGEST,
    verifier: 'worker-cosign',
    verifiedAt: '2026-09-16T10:00:00Z',
    signature: {
      signed: true,
      verified: true,
      keyId: 'cosign-key-1',
      signatureDigest: SIG_DIGEST,
      signedDigest: OUTPUT_DIGEST,
      tool: 'cosign v2.4.1',
    },
    sbom: {
      format: 'cyclonedx-json',
      sbomDigest: SBOM_DIGEST,
      attestationDigest: ATT_DIGEST,
      componentCount: 142,
      verified: true,
      tool: 'syft v1.20.0',
    },
    provenance: {
      attestationDigest: ATT_DIGEST,
      sourceDigest: SOURCE_DIGEST,
      subjectDigest: OUTPUT_DIGEST,
      buildRef: 'https://example-org.visualstudio.com/SecureImages/_build/results?buildId=123',
      verified: true,
    },
  };
}

describe('validateSupplyChainEvidence — tam kanıt', () => {
  const { supplyChain } = validateSupplyChainEvidence(fullEvidence(), {
    expectedOutputDigest: OUTPUT_DIGEST,
    rawContent: JSON.stringify(fullEvidence()),
  });

  it('policy boolean\'larını üretir (signature/sbom/provenance = true)', () => {
    expect(supplyChain.signature).toBe(true);
    expect(supplyChain.sbom).toBe(true);
    expect(supplyChain.provenance).toBe(true);
  });

  it('UI için zengin detay taşır', () => {
    expect(supplyChain.details.sbom).toMatchObject({ format: 'cyclonedx-json', componentCount: 142 });
    expect(supplyChain.details.signature.keyId).toBe('cosign-key-1');
    expect(supplyChain.details.provenance.sourceDigest).toBe(SOURCE_DIGEST);
    expect(supplyChain.verifier).toBe('worker-cosign');
    expect(supplyChain.outputDigest).toBe(OUTPUT_DIGEST);
  });
});

describe('validateSupplyChainEvidence — kısmi / esnek', () => {
  it('yalnız SBOM gelirse signature/provenance false olur', () => {
    const { supplyChain } = validateSupplyChainEvidence(
      {
        outputDigest: OUTPUT_DIGEST,
        sbom: { format: 'cyclonedx-json', sbomDigest: SBOM_DIGEST, componentCount: 5, verified: true },
      },
      { expectedOutputDigest: OUTPUT_DIGEST },
    );
    expect(supplyChain.sbom).toBe(true);
    expect(supplyChain.signature).toBe(false);
    expect(supplyChain.provenance).toBe(false);
  });

  it('imza signed ama verified değilse ok=false', () => {
    const evidence = fullEvidence();
    evidence.signature.verified = false;
    const { supplyChain } = validateSupplyChainEvidence(evidence, { expectedOutputDigest: OUTPUT_DIGEST });
    expect(supplyChain.signature).toBe(false);
  });
});

describe('validateSupplyChainEvidence — reddetmeler', () => {
  it('outputDigest uyuşmazsa reddeder', () => {
    expect(() =>
      validateSupplyChainEvidence(fullEvidence(), { expectedOutputDigest: `sha256:${'f'.repeat(64)}` }),
    ).toThrow(SupplyChainEvidenceValidationError);
  });

  it('imza başka digest üzerindeyse reddeder (bağ kopması)', () => {
    const evidence = fullEvidence();
    evidence.signature.signedDigest = SOURCE_DIGEST;
    expect(() =>
      validateSupplyChainEvidence(evidence, { expectedOutputDigest: OUTPUT_DIGEST }),
    ).toThrow(/signedDigest must match/);
  });

  it('geçersiz SBOM formatı reddeder', () => {
    const evidence = fullEvidence();
    evidence.sbom.format = 'text';
    expect(() =>
      validateSupplyChainEvidence(evidence, { expectedOutputDigest: OUTPUT_DIGEST }),
    ).toThrow(/cyclonedx-json or spdx-json/);
  });

  it('provenance subject digest çıktı digest\'iyle eşleşmezse reddeder', () => {
    const evidence = fullEvidence();
    evidence.provenance.subjectDigest = SOURCE_DIGEST;
    expect(() =>
      validateSupplyChainEvidence(evidence, { expectedOutputDigest: OUTPUT_DIGEST }),
    ).toThrow(/subjectDigest must match/);
  });

  it('geçersiz beklenen digest reddeder', () => {
    expect(() =>
      validateSupplyChainEvidence(fullEvidence(), { expectedOutputDigest: 'not-a-digest' }),
    ).toThrow(/valid immutable approved output digest/);
  });
});
