function scoreFromCvss(cvss = {}) {
  const sources = ['nvd', 'redhat', 'ghsa', 'ubuntu'];

  for (const source of sources) {
    const score = cvss[source]?.V3Score ?? cvss[source]?.V2Score;
    if (Number.isFinite(score)) {
      return score;
    }
  }

  for (const value of Object.values(cvss)) {
    const score = value?.V3Score ?? value?.V2Score;
    if (Number.isFinite(score)) {
      return score;
    }
  }

  return 0;
}

function vectorFromCvss(cvss = {}) {
  const sources = ['nvd', 'redhat', 'ghsa', 'ubuntu'];

  for (const source of sources) {
    const vector = cvss[source]?.V3Vector ?? cvss[source]?.V2Vector;
    if (vector) {
      return vector;
    }
  }

  for (const value of Object.values(cvss)) {
    const vector = value?.V3Vector ?? value?.V2Vector;
    if (vector) {
      return vector;
    }
  }

  return '';
}

function normalizeSeverity(severity = 'Unknown') {
  const lower = severity.toLowerCase();
  return lower.charAt(0).toUpperCase() + lower.slice(1);
}

function findingStatus(vulnerability) {
  if (vulnerability.FixedVersion) {
    return 'Fix available';
  }

  return vulnerability.Status === 'fixed' ? 'Fix available' : 'No fix';
}

export function normalizeTrivyScan(scan) {
  const repoTag = scan.Metadata?.RepoTags?.[0] || scan.ArtifactName || 'unknown:image';
  const repoDigest = scan.Metadata?.RepoDigests?.[0] || '';
  const digest = repoDigest.split('@')[1] || scan.Metadata?.ImageID || '';
  const os = [scan.Metadata?.OS?.Family, scan.Metadata?.OS?.Name].filter(Boolean).join(' ');
  const findings = [];

  for (const result of scan.Results || []) {
    if (result.Class && result.Class !== 'os-pkgs') {
      continue;
    }

    for (const vulnerability of result.Vulnerabilities || []) {
      findings.push({
        cve: vulnerability.VulnerabilityID,
        package: vulnerability.PkgName,
        installed: vulnerability.InstalledVersion || '-',
        fixed: vulnerability.FixedVersion || '-',
        severity: normalizeSeverity(vulnerability.Severity),
        cvss: scoreFromCvss(vulnerability.CVSS),
        cvssVector: vectorFromCvss(vulnerability.CVSS),
        epss: null,
        status: findingStatus(vulnerability),
        title: vulnerability.Title || vulnerability.VulnerabilityID,
        description: vulnerability.Description || '',
        primaryUrl: vulnerability.PrimaryURL || '',
        target: result.Target || '',
        class: result.Class || '',
        type: result.Type || '',
      });
    }
  }

  return {
    id: repoTag,
    image: repoTag,
    digest,
    os,
    scanner: 'Trivy',
    scannedAt: new Date().toISOString().replace('T', ' ').slice(0, 16),
    artifactType: scan.ArtifactType || 'container_image',
    schemaVersion: scan.SchemaVersion || 2,
    findings,
  };
}
