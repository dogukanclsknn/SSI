// SSI — what of a built OS template can be downloaded through SSI, and from where. Pure: no
// I/O (the screen uses it too). The files stay in the Azure DevOps run that built the template;
// SSI streams them (src/server/azureDevOpsClient.js openArtifact) and never keeps a copy.
//
//   Ubuntu, per-format layout   one artifact per disk format (os-template-ubuntu-qcow2, -ova,
//                               -vhdx) and the evidence artifact
//   Ubuntu, combined (legacy)   all three formats in os-template-ubuntu-images, and the evidence
//   Windows                     nothing: the ISO stays on the Windows build machine
//
// Only Built and Approved templates are offered: a requested one has no files yet, and a
// rejected one is not to be used. Azure DevOps hands every artifact out as a zip.
// No import of osTemplate.js: it builds its summary with this module (one direction only).

export const DOWNLOADABLE_STATES = Object.freeze(['Built', 'Approved']);
export const UBUNTU_EVIDENCE_ARTIFACT = 'os-template-ubuntu-evidence';
export const UBUNTU_COMBINED_ARTIFACT = 'os-template-ubuntu-images';
export const ubuntuFormatArtifact = (format) => `os-template-ubuntu-${format}`;
const downloadIdPattern = /^[a-z0-9]{2,20}$/;

export class OsTemplateDownloadError extends Error {
  constructor(message, statusCode = 409) {
    super(message);
    this.name = 'OsTemplateDownloadError';
    this.statusCode = statusCode;
  }
}

const PLATFORM_LABELS = {
  qcow2: 'Proxmox / KVM',
  ova: 'VMware vSphere',
  vhdx: 'Hyper-V',
};

// How a result's files were published. Results recorded before the layout was stored
// (OST-0002 and older, 2026-11-25) have no `layout`; their path names the one combined artifact.
export function artifactLayoutOf(location) {
  if (location?.layout === 'combined' || location?.layout === 'per-format') return location.layout;
  const artifact = location?.artifact || String(location?.path || '').split('/')[0];
  return artifact === UBUNTU_COMBINED_ARTIFACT ? 'combined' : 'per-format';
}

// The downloads of one build request: [{ id, kind, label, artifact, runId, fileName,
// sizeBytes, files: [{ file, format, sizeBytes, sha256 }] }]. Empty when nothing can be
// downloaded (with the reason from downloadsUnavailableReason).
export function osTemplateDownloads(build) {
  if (downloadsUnavailableReason(build)) return [];
  const { manifest, location } = build.result;
  const base = `${manifest.template.name}-${manifest.template.version}`;
  const runId = location.adoBuildId;
  const evidence = {
    id: 'evidence',
    kind: 'evidence',
    label: 'Evidence (scan reports, package lists, manifest)',
    artifact: UBUNTU_EVIDENCE_ARTIFACT,
    runId,
    fileName: `${base}-evidence.zip`,
    sizeBytes: null,
    files: [],
  };
  const files = manifest.artifacts.map(({ file, format, sizeBytes, sha256 }) => ({
    file,
    format,
    sizeBytes,
    sha256,
  }));
  if (artifactLayoutOf(location) === 'combined') {
    return [
      {
        id: 'images',
        kind: 'image',
        label: 'QCOW2 + OVA + VHDX (one archive)',
        artifact: UBUNTU_COMBINED_ARTIFACT,
        runId,
        fileName: `${base}-images.zip`,
        sizeBytes: files.reduce((sum, item) => sum + item.sizeBytes, 0),
        files,
      },
      evidence,
    ];
  }
  return [
    ...files.map((item) => ({
      id: item.format,
      kind: 'image',
      label: `${item.format.toUpperCase()} · ${PLATFORM_LABELS[item.format] || item.format}`,
      artifact: ubuntuFormatArtifact(item.format),
      runId,
      fileName: `${item.file}.zip`,
      sizeBytes: item.sizeBytes,
      files: [item],
    })),
    evidence,
  ];
}

// Why a build request offers no download, or '' when it does.
export function downloadsUnavailableReason(build) {
  if (!build?.result?.manifest) return 'The template has not been built yet.';
  if (!DOWNLOADABLE_STATES.includes(build.status)) {
    return `A ${String(build.status).toLowerCase()} template is not offered for download.`;
  }
  if (build.request?.os !== 'ubuntu-24.04') {
    return 'The Windows template ISO stays on the Windows build machine; it is not downloaded through SSI.';
  }
  if (!build.result.location?.adoBuildId) return 'The template has no Azure DevOps run recorded.';
  return '';
}

// The one download a request names, or an error that says why not.
export function findOsTemplateDownload(build, downloadId) {
  if (!downloadIdPattern.test(String(downloadId || ''))) {
    throw new OsTemplateDownloadError('Unknown download.', 404);
  }
  const reason = downloadsUnavailableReason(build);
  if (reason) throw new OsTemplateDownloadError(reason, 409);
  const download = osTemplateDownloads(build).find((item) => item.id === downloadId);
  if (!download) throw new OsTemplateDownloadError('Unknown download.', 404);
  return download;
}
