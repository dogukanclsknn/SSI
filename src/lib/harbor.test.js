import { describe, expect, it } from 'vitest';
import {
  HARBOR_VULNERABILITY_REPORT_MIME,
  collectAllPages,
  encodeHarborRepositoryName,
  findHarborScanOverview,
  harborRelativeRepositoryName,
  harborScanStatus,
  isCosignAccessoryArtifact,
  isHarborScanComplete,
  mapHarborArtifact,
  normalizeHarborVulnerabilityReport,
  parseHarborProjects,
} from './harbor.js';

const artifact = {
  digest: 'sha256:4e7d1bf6c4a2',
  mime_type: 'application/vnd.oci.image.manifest.v1+json',
  push_time: '2026-07-17T09:42:00Z',
  tags: [{ name: '3.20' }],
  scan_overview: {
    [HARBOR_VULNERABILITY_REPORT_MIME]: {
      scan_status: 'Success',
      end_time: '2026-07-17T09:43:08Z',
      scanner: { name: 'Trivy', version: 'v0.62.1' },
    },
  },
};

const harborReport = {
  generated_at: '2026-07-17T09:43:08.225Z',
  artifact: {
    repository: 'ssi-images/ssi-test-alpine',
    digest: 'sha256:4e7d1bf6c4a2',
    tag: '3.20',
  },
  scanner: { name: 'Trivy', vendor: 'Aqua Security', version: 'v0.62.1' },
  vulnerabilities: [
    {
      id: 'CVE-2024-3094',
      package: 'xz-utils',
      version: '5.2.5-r0',
      fix_version: '5.2.5-r1',
      severity: 'Critical',
      description: 'Backdoor in XZ Utils',
      links: ['https://avd.aquasec.com/nvd/cve-2024-3094'],
      preferred_cvss: {
        score_v3: 10,
        vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
      },
    },
    {
      id: 'CVE-2022-37434',
      package: 'zlib',
      version: '1.2.13-r1',
      severity: 'Medium',
      cvss: { nvd: { V3Score: 6.5 } },
    },
  ],
};

describe('Harbor vulnerability adapter', () => {
  it('scan overview durumunu Harbor MIME anahtarından okur', () => {
    const overview = findHarborScanOverview(artifact);

    expect(harborScanStatus(overview)).toBe('success');
    expect(isHarborScanComplete(overview)).toBe(true);
  });

  it('Harbor vulnerability reportunu Scan Results modeline çevirir', () => {
    const report = normalizeHarborVulnerabilityReport({
      report: harborReport,
      project: 'ssi-images',
      repository: 'ssi-test-alpine',
      artifact,
      overview: findHarborScanOverview(artifact),
    });

    expect(report).toMatchObject({
      id: 'ssi-images/ssi-test-alpine:3.20',
      image: 'ssi-images/ssi-test-alpine:3.20',
      digest: 'sha256:4e7d1bf6c4a2',
      scanner: 'Trivy',
      scannedAt: '2026-07-17 09:43',
    });
    expect(report.findings).toEqual([
      expect.objectContaining({
        cve: 'CVE-2024-3094',
        package: 'xz-utils',
        installed: '5.2.5-r0',
        fixed: '5.2.5-r1',
        severity: 'Critical',
        cvss: 10,
        status: 'Fix available',
        class: 'unknown',
      }),
      expect.objectContaining({
        cve: 'CVE-2022-37434',
        package: 'zlib',
        fixed: '-',
        cvss: 6.5,
        status: 'No fix',
      }),
    ]);
  });
});

describe('Harbor repository adı kodlaması', () => {
  it('iç içe depo adını çift kodlar ve tek çözümde ham slash bırakmaz', () => {
    const encoded = encodeHarborRepositoryName('approved/ssi-remediation-test');

    expect(encoded).toBe('approved%252Fssi-remediation-test');
    expect(decodeURIComponent(encoded)).toBe('approved%2Fssi-remediation-test');
  });

  it('düz depo adını tek kodlama ile aynı bırakır', () => {
    expect(encodeHarborRepositoryName('ssi-test-alpine')).toBe('ssi-test-alpine');
    expect(encodeHarborRepositoryName('ssi-test-alpine')).toBe(
      encodeURIComponent('ssi-test-alpine'),
    );
  });

  it('çok seviyeli iç içe adın her slashını kodlar', () => {
    expect(encodeHarborRepositoryName('approved/team-a/ssi-remediation-test')).toBe(
      'approved%252Fteam-a%252Fssi-remediation-test',
    );
  });

  it('boş, null ve undefined girdide hata atmaz', () => {
    expect(encodeHarborRepositoryName('')).toBe('');
    expect(encodeHarborRepositoryName(null)).toBe('');
    expect(encodeHarborRepositoryName(undefined)).toBe('');
  });
});

describe('parseHarborProjects', () => {
  it('virgülle ayrık listeyi ayrıştırır, boşlukları temizler', () => {
    expect(parseHarborProjects(' ssi-images , team-x ')).toEqual(['ssi-images', 'team-x']);
  });

  it('tekrarlı ve boş girdileri eler, sırayı korur', () => {
    expect(parseHarborProjects('a,,b,a, ,b')).toEqual(['a', 'b']);
  });

  it('liste boşsa tek proje fallback değerine düşer', () => {
    expect(parseHarborProjects('', 'ssi-images')).toEqual(['ssi-images']);
    expect(parseHarborProjects(undefined, ' solo ')).toEqual(['solo']);
  });

  it('hem liste hem fallback boşsa boş dizi döner', () => {
    expect(parseHarborProjects('', '')).toEqual([]);
    expect(parseHarborProjects(null, null)).toEqual([]);
  });
});

describe('harborRelativeRepositoryName', () => {
  it('proje önekini kaldırır', () => {
    expect(harborRelativeRepositoryName('ssi-images', 'ssi-images/nginx-src')).toBe('nginx-src');
  });

  it('repository nesnesinin name alanını kullanır', () => {
    expect(harborRelativeRepositoryName('team-x', { name: 'team-x/api/gateway' })).toBe('api/gateway');
  });

  it('önek eşleşmezse adı olduğu gibi bırakır', () => {
    expect(harborRelativeRepositoryName('team-x', 'other/repo')).toBe('other/repo');
  });
});

describe('mapHarborArtifact', () => {
  const artifactWithScan = {
    digest: 'sha256:aaaabbbbccccddddeeee',
    push_time: '2026-08-01T10:00:00Z',
    tags: [{ name: '1.0' }],
    size: 42 * 1024 * 1024,
    scan_overview: {
      [HARBOR_VULNERABILITY_REPORT_MIME]: {
        scan_status: 'Success',
        end_time: '2026-08-01T10:05:00Z',
        summary: { summary: { Critical: 2, High: 1, Medium: 0, Low: 3 } },
      },
    },
  };

  it('proje-farkında benzersiz id ve project alanı üretir', () => {
    const image = mapHarborArtifact({
      project: 'ssi-images',
      repository: 'ssi-images/nginx-src',
      artifact: artifactWithScan,
    });

    expect(image).toMatchObject({
      id: 'harbor-ssi-images-nginx-src-1-0',
      name: 'ssi-images/nginx-src',
      version: '1.0',
      project: 'ssi-images',
      source: 'Harbor',
      critical: 2,
      high: 1,
      low: 3,
      status: 'Blocked',
      maxCvss: 9.8,
      fullDigest: 'sha256:aaaabbbbccccddddeeee',
      repository: 'nginx-src',
      signature: false,
      sbom: false,
    });
  });

  it('aynı repo adı farklı projelerde çakışmayan id üretir', () => {
    const a = mapHarborArtifact({ project: 'proj-a', repository: 'proj-a/app', artifact: artifactWithScan });
    const b = mapHarborArtifact({ project: 'proj-b', repository: 'proj-b/app', artifact: artifactWithScan });
    expect(a.id).not.toBe(b.id);
    expect(a.project).toBe('proj-a');
    expect(b.project).toBe('proj-b');
  });
});

describe('isCosignAccessoryArtifact', () => {
  const hex = 'b7d05173263d803b1544242aca7a98cc7a33771c5df3811600e1ce7cde407f5b';
  const artifact = (...names) => ({ digest: `sha256:${'c'.repeat(64)}`, tags: names.map((name) => ({ name })) });

  it('recognises Cosign signature, attestation and SBOM artifacts by their tag', () => {
    for (const suffix of ['sig', 'att', 'sbom']) {
      expect(isCosignAccessoryArtifact(artifact(`sha256-${hex}.${suffix}`))).toBe(true);
    }
  });

  it('keeps real images, untagged manifests and anything with a real tag', () => {
    expect(isCosignAccessoryArtifact(artifact('alpine'))).toBe(false);
    expect(isCosignAccessoryArtifact(artifact(`sha256-${hex}.att`, 'verified-r3'))).toBe(false);
    expect(isCosignAccessoryArtifact(artifact())).toBe(false);
    expect(isCosignAccessoryArtifact({ digest: `sha256:${hex}` })).toBe(false);
    expect(isCosignAccessoryArtifact(artifact(`sha256-${hex}.att.bak`))).toBe(false);
    expect(isCosignAccessoryArtifact(artifact('sha256-abc.sig'))).toBe(false);
  });
});

describe('collectAllPages', () => {
  it('page_size dolu sayfalar boyunca toplar, kısa sayfada durur', async () => {
    const pages = {
      1: Array.from({ length: 100 }, (_, i) => i),
      2: Array.from({ length: 30 }, (_, i) => 100 + i),
    };
    const calls = [];
    const result = await collectAllPages(
      (page) => {
        calls.push(page);
        return Promise.resolve(pages[page] || []);
      },
      { pageSize: 100 },
    );

    expect(result).toHaveLength(130);
    expect(calls).toEqual([1, 2]);
  });

  it('ilk sayfa kısa ise tek çağrıda durur', async () => {
    const calls = [];
    const result = await collectAllPages(
      (page) => {
        calls.push(page);
        return Promise.resolve([1, 2, 3]);
      },
      { pageSize: 100 },
    );

    expect(result).toEqual([1, 2, 3]);
    expect(calls).toEqual([1]);
  });

  it('maxPages sınırını aşmaz (kaçak döngü koruması)', async () => {
    let calls = 0;
    const result = await collectAllPages(
      () => {
        calls += 1;
        return Promise.resolve(Array.from({ length: 2 }, () => 0));
      },
      { pageSize: 2, maxPages: 3 },
    );

    expect(calls).toBe(3);
    expect(result).toHaveLength(6);
  });
});
