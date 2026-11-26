// SSI — image operating system classification (remediation scope guard).
//
// Copacetic (Copa) patches Linux OS packages only. Windows images cannot be patched in
// place, and Windows scanning is deferred to a later release (see the Windows decision
// document in the project). Until then a Windows image is kept out of remediation with a
// clear message: the open-source scanners do not cover the Windows OS layer, so treating
// such an image like a Linux one could show "0 findings" for an image that was never
// really scanned.
//
// This module is the single place that decides whether an image's OS is in scope.

export const OS_KIND = { LINUX: 'linux', WINDOWS: 'windows', UNKNOWN: 'unknown' };

// Linux distributions Copa patches (Trivy Metadata.OS.Family values).
// wolfi/chainguard are deliberately absent: Copa does not patch them.
const LINUX_FAMILIES = new Set([
  'debian', 'ubuntu', 'alpine', 'redhat', 'rhel', 'centos', 'rocky', 'alma', 'almalinux',
  'oracle', 'ol', 'amazon', 'amazonlinux', 'suse', 'sles', 'opensuse', 'photon',
  'mariner', 'cbl-mariner', 'azurelinux', 'bottlerocket', 'fedora', 'minimos',
]);

// Text markers that identify a Windows image (OS family or base image name).
const WINDOWS_MARKERS = ['windows', 'servercore', 'nanoserver', 'server core', 'nano server', 'ltsc'];

function normalize(value) {
  return String(value || '').trim().toLowerCase();
}

// OS family from "debian", "debian 12" or "windows server core".
export function osFamilyOf(osString) {
  const text = normalize(osString);
  if (!text) return '';
  return text.split(/[\s/_-]+/).filter(Boolean)[0] || '';
}

// Returns { family, kind, remediable }.
export function classifyImageOs(osString) {
  const text = normalize(osString);
  const family = osFamilyOf(text);

  if (WINDOWS_MARKERS.some((marker) => text.includes(marker))) {
    return { family: family || 'windows', kind: OS_KIND.WINDOWS, remediable: false };
  }

  if (family && LINUX_FAMILIES.has(family)) {
    return { family, kind: OS_KIND.LINUX, remediable: true };
  }

  // Unknown or empty OS: the only thing we know is that it is not Windows. Harbor does not
  // always report the OS, so the normal Copa path is tried; eligibility is filtered per
  // finding, and the canonical Trivy report re-classifies the image with its real OS.
  return { family: family || 'unknown', kind: OS_KIND.UNKNOWN, remediable: true };
}

export function isWindowsImage(osString) {
  return classifyImageOs(osString).kind === OS_KIND.WINDOWS;
}

export function isRemediableOs(osString) {
  return classifyImageOs(osString).remediable;
}
