#!/usr/bin/env bash
# Scans the guest's operating system packages with the Trivy binary and vulnerability database
# the build host uploaded to SCAN_DIR: the guest never reaches a vulnerability feed itself.
# Writes, readable for the download step:
#   SCAN_DIR/out/scan-<phase>.json      Trivy JSON (OS packages, vulnerabilities only)
#   SCAN_DIR/out/packages-<phase>.tsv   installed packages: name <TAB> version
# Runs as root inside the build VM. Usage: scan.sh before|after
set -euo pipefail

phase="${1:-${SCAN_PHASE:-}}"
case "${phase}" in
  before | after) ;;
  *)
    echo 'usage: scan.sh before|after' >&2
    exit 2
    ;;
esac
SCAN_DIR="${SCAN_DIR:-/var/tmp/ssi-scan}"
OUT_DIR="${SCAN_DIR}/out"
TRIVY="${SCAN_DIR}/trivy"

# The file upload does not always keep the executable bit.
[[ -f "${TRIVY}" ]] && chmod 0755 "${TRIVY}"
if [[ ! -x "${TRIVY}" || ! -d "${SCAN_DIR}/cache/db" ]]; then
  echo "The Trivy binary or database is missing under ${SCAN_DIR}; the host upload failed." >&2
  exit 2
fi
mkdir -p "${OUT_DIR}"

"${TRIVY}" rootfs \
  --cache-dir "${SCAN_DIR}/cache" \
  --skip-db-update --skip-java-db-update --offline-scan --disable-telemetry --quiet \
  --scanners vuln --pkg-types os \
  --skip-dirs "${SCAN_DIR}" \
  --format json --output "${OUT_DIR}/scan-${phase}.json" \
  /

dpkg-query -W -f='${Package}\t${Version}\n' | LC_ALL=C sort > "${OUT_DIR}/packages-${phase}.tsv"
uname -r > "${OUT_DIR}/kernel-${phase}.txt"
chmod 0644 "${OUT_DIR}"/*
echo "Scan '${phase}': $(wc -l < "${OUT_DIR}/packages-${phase}.tsv") packages, kernel $(uname -r)."
