import { describe, it, expect } from 'vitest';
import { evaluatePolicy, cvssTone, epssTone } from './security.js';

describe('cvssTone', () => {
  it('CVSS skorunu doğru tona eşler', () => {
    expect(cvssTone(9.1)).toBe('critical');
    expect(cvssTone(7)).toBe('high');
    expect(cvssTone(4)).toBe('medium');
    expect(cvssTone(3.9)).toBe('low');
  });
});

describe('epssTone', () => {
  it('EPSS olasılığını doğru tona eşler', () => {
    expect(epssTone(0.62)).toBe('critical');
    expect(epssTone(0.1)).toBe('high');
    expect(epssTone(0.05)).toBe('low');
  });
});

describe('evaluatePolicy', () => {
  const base = {
    name: 'secure/node',
    digest: 'sha256:abc',
    signature: true,
    sbom: true,
    type: 'Base',
    status: 'Approved',
    critical: 0,
    high: 0,
  };

  it('temiz güvenli imajı geçirir', () => {
    const result = evaluatePolicy(base);
    expect(result.pass).toBe(true);
    expect(result.findings).toHaveLength(1);
  });

  it('High CVE olan imajı bloklar', () => {
    const result = evaluatePolicy({ ...base, high: 2 });
    expect(result.pass).toBe(false);
    expect(result.findings.some((f) => f.includes('CVE'))).toBe(true);
  });

  it('Debug imaj ve eksik imzayı bloklar', () => {
    const result = evaluatePolicy({ ...base, type: 'Debug', signature: false });
    expect(result.pass).toBe(false);
    expect(result.findings.length).toBeGreaterThanOrEqual(2);
  });
});
