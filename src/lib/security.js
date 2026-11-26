// Saf güvenlik/politika mantığı — UI'dan ayrık tutulur ki birim testi yazılabilsin.

// Kubernetes admission-benzeri politika değerlendirmesi.
export function evaluatePolicy(image) {
  const findings = [];

  if (!image.name.startsWith('secure/') && !image.name.startsWith('apps/')) {
    findings.push('The image is outside the approved registry namespace.');
  }
  if (!image.digest.startsWith('sha256:')) {
    findings.push('Digest pin eksik.');
  }
  if (!image.signature) {
    findings.push('No Cosign signature.');
  }
  if (!image.sbom) {
    findings.push('No SBOM.');
  }
  if (image.type === 'Debug') {
    findings.push('Debug images cannot be used in production.');
  }
  if (image.status === 'Deprecated') {
    findings.push('New deployments of a deprecated image are blocked.');
  }
  if (image.critical > 0 || image.high > 0) {
    findings.push('Critical or High CVEs exceed the policy limit.');
  }

  return {
    pass: findings.length === 0,
    findings: findings.length
      ? findings
      : ['Registry, digest, signature, SBOM and CVE checks passed.'],
  };
}

// CVSS skorunu renk tonuna eşler (severity görselleştirmesi).
export function cvssTone(score) {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

// EPSS (istismar olasılığı) skorunu renk tonuna eşler.
export function epssTone(score) {
  if (score >= 0.5) return 'critical';
  if (score >= 0.1) return 'high';
  return 'low';
}
