#!/usr/bin/env bash
# SSI OS template — Ubuntu 24.04 offline build (docs/os-template-poc.md, "Ubuntu (offline build)").
# The same journey as the Windows build, without booting a VM: the official Ubuntu cloud image is
# changed in place with libguestfs (virt-customize), so the build host needs neither vCenter nor
# nested virtualization (KVM is used when /dev/kvm is there, otherwise qemu emulates).
#
#   pin      the cloud image is verified against the SHA-256 the request pinned (and, with a
#            keyring, against Canonical's signed SHA256SUMS); a cached copy is re-verified
#   scan     Trivy scans the guest's dpkg database offline (database prepared by the host)
#   patch    guest/patch.sh (apt full-upgrade, VMware and QEMU agents), guest/prune-kernels.sh
#   rescan   the second scan; host/template-report.mjs stops the build if a fixable CVE is left
#   seal     guest/seal.sh, then the seal is verified on the disk
#   export   host/export.sh: QCOW2 (Proxmox/KVM), OVA (vSphere), VHDX (Hyper-V), SHA256SUMS
#   manifest template-manifest.json (ssi.os-template-manifest/v1)
#
# Environment (required): BASE_IMAGE_URL, BASE_IMAGE_SHA256, TEMPLATE_NAME, BUILD_ID, WORK_DIR,
#   TRIVY_CACHE_DIR (holds db/ of `trivy image --download-db-only`).
# Optional: TEMPLATE_VERSION (24.04-<UTC date>-<BUILD_ID>), CACHE_DIR (verified base images,
#   default WORK_DIR/cache), CLOUD_IMAGE_KEYRING (gpgv keyring of the Ubuntu cloud image signing
#   key), APT_MIRROR, APT_PROXY (http://host:port, build only), APT_CA_FILE (CA of a TLS-inspecting
#   proxy, build only), DISK_SIZE_GB (grow the root partition), BUILD_SMP (2), BUILD_MEMORY_MB
#   (2048), MAX_DB_AGE_HOURS (72), TRIVY (trivy).
# Exit codes: 0 template built, 1 the gate refused it, 2 invalid input or a failed step.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
poc="$(cd "${here}/.." && pwd)"

fail() {
  echo "build-ubuntu-template: $*" >&2
  exit 2
}
step() { printf '\n== %s ==\n' "$*"; }
# Exit code 1 means only "the gate refused the template"; any other failure is 2.
trap 'echo "build-ubuntu-template: failed at line ${LINENO}." >&2; exit 2' ERR

: "${BASE_IMAGE_URL:?}" "${BASE_IMAGE_SHA256:?}" "${TEMPLATE_NAME:?}" "${BUILD_ID:?}" "${WORK_DIR:?}" "${TRIVY_CACHE_DIR:?}"
BASE_IMAGE_SHA256="${BASE_IMAGE_SHA256,,}"
TEMPLATE_VERSION="${TEMPLATE_VERSION:-24.04-$(date -u +%Y%m%d)-${BUILD_ID}}"
CACHE_DIR="${CACHE_DIR:-${WORK_DIR}/cache}"
BUILD_SMP="${BUILD_SMP:-2}"
BUILD_MEMORY_MB="${BUILD_MEMORY_MB:-2048}"
MAX_DB_AGE_HOURS="${MAX_DB_AGE_HOURS:-72}"
TRIVY="${TRIVY:-trivy}"
export LIBGUESTFS_BACKEND="${LIBGUESTFS_BACKEND:-direct}"

# ── inputs: every value that reaches a command line or the guest is checked here ─────────────
[[ "${BASE_IMAGE_URL}" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._~/-]*/([A-Za-z0-9._-]+\.img)$ ]] ||
  fail 'BASE_IMAGE_URL must be an https URL of a .img file, without credentials or query.'
base_file="${BASH_REMATCH[2]}"
[[ "${BASE_IMAGE_SHA256}" =~ ^[0-9a-f]{64}$ ]] || fail 'BASE_IMAGE_SHA256 must be 64 hex characters; the build refuses an unpinned image.'
[[ "${TEMPLATE_NAME}" =~ ^[a-z0-9][a-z0-9-]{1,62}$ ]] || fail 'TEMPLATE_NAME is invalid.'
[[ "${TEMPLATE_VERSION}" =~ ^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$ ]] || fail 'TEMPLATE_VERSION is invalid.'
[[ "${BUILD_ID}" =~ ^[0-9A-Za-z._-]{1,64}$ ]] || fail 'BUILD_ID is invalid.'
[[ "${BUILD_SMP}" =~ ^[1-9][0-9]?$ && "${BUILD_MEMORY_MB}" =~ ^[1-9][0-9]{2,5}$ ]] || fail 'BUILD_SMP or BUILD_MEMORY_MB is invalid.'
[[ "${MAX_DB_AGE_HOURS}" =~ ^[1-9][0-9]{0,3}$ ]] || fail 'MAX_DB_AGE_HOURS is invalid.'
[[ -z "${DISK_SIZE_GB:-}" || "${DISK_SIZE_GB}" =~ ^[1-9][0-9]{0,3}$ ]] || fail 'DISK_SIZE_GB must be a whole number of GiB.'
if [[ -n "${APT_MIRROR:-}" && ! "${APT_MIRROR}" =~ ^https?://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~/-]*)?$ ]]; then
  fail 'APT_MIRROR must be an http(s) URL without credentials or query.'
fi
if [[ -n "${APT_PROXY:-}" && ! "${APT_PROXY}" =~ ^https?://[A-Za-z0-9.-]+:[0-9]{1,5}/?$ ]]; then
  fail 'APT_PROXY must be http(s)://host:port, without credentials.'
fi
[[ -z "${APT_CA_FILE:-}" || -f "${APT_CA_FILE}" ]] || fail 'APT_CA_FILE is not a file.'
[[ -z "${CLOUD_IMAGE_KEYRING:-}" || -f "${CLOUD_IMAGE_KEYRING}" ]] || fail 'CLOUD_IMAGE_KEYRING is not a file.'
[[ -d "${TRIVY_CACHE_DIR}/db" ]] || fail "${TRIVY_CACHE_DIR}/db not found; prepare the Trivy database first."

for tool in virt-customize virt-resize virt-sparsify guestfish qemu-img dpkg-query sha256sum curl node; do
  command -v "${tool}" >/dev/null || fail "${tool} is required."
done
command -v "${TRIVY}" >/dev/null || fail "Trivy (${TRIVY}) is required."
if [[ -n "${CLOUD_IMAGE_KEYRING:-}" ]]; then command -v gpgv >/dev/null || fail 'gpgv is required for CLOUD_IMAGE_KEYRING.'; fi

if [[ -e "${WORK_DIR}/out" || -e "${WORK_DIR}/disk.qcow2" ]]; then
  fail "${WORK_DIR} holds an earlier build; use a new directory."
fi
reports="${WORK_DIR}/reports"
out="${WORK_DIR}/out"
stage="${WORK_DIR}/stage"
disk="${WORK_DIR}/disk.qcow2"
mkdir -p "${reports}" "${out}" "${stage}/ssi-build" "${CACHE_DIR}"
# libguestfs and virt-sparsify keep their large temporary files here, not in a small /tmp.
export TMPDIR="${WORK_DIR}/tmp"
mkdir -p "${TMPDIR}"

guest_args=(--smp "${BUILD_SMP}" --memsize "${BUILD_MEMORY_MB}")
[[ -e /dev/kvm && -w /dev/kvm ]] || echo 'No usable /dev/kvm: libguestfs runs qemu without acceleration (slower).'

# ── pin: the base image ─────────────────────────────────────────────────────────────────────
step "Base image ${base_file}"
cached="${CACHE_DIR}/${BASE_IMAGE_SHA256}.img"
if [[ -f "${cached}" ]]; then
  echo "Using the cached copy; verifying it again."
else
  curl -fsSL --retry 3 --proto '=https' -o "${cached}.part" "${BASE_IMAGE_URL}"
  mv "${cached}.part" "${cached}"
fi
actual="$(sha256sum "${cached}" | cut -d' ' -f1)"
if [[ "${actual}" != "${BASE_IMAGE_SHA256}" ]]; then
  mv "${cached}" "${cached}.rejected"
  fail "The base image hash is ${actual}, not the pinned ${BASE_IMAGE_SHA256}; the copy was set aside."
fi
echo "SHA-256 matches the pin: ${actual}"
if [[ -n "${CLOUD_IMAGE_KEYRING:-}" ]]; then
  sums_url="${BASE_IMAGE_URL%/*}/SHA256SUMS"
  curl -fsSL --retry 3 --proto '=https' -o "${reports}/base-SHA256SUMS" "${sums_url}"
  curl -fsSL --retry 3 --proto '=https' -o "${reports}/base-SHA256SUMS.gpg" "${sums_url}.gpg"
  gpgv --keyring "${CLOUD_IMAGE_KEYRING}" "${reports}/base-SHA256SUMS.gpg" "${reports}/base-SHA256SUMS" ||
    fail 'The signature of SHA256SUMS does not verify with CLOUD_IMAGE_KEYRING.'
  grep -Eq "^${BASE_IMAGE_SHA256} [ *]${base_file}$" "${reports}/base-SHA256SUMS" ||
    fail "The signed SHA256SUMS does not list ${base_file} with the pinned hash."
  echo 'The pinned hash is in the SHA256SUMS signed by the cloud image key.'
fi

if [[ -n "${DISK_SIZE_GB:-}" ]]; then
  qemu-img create -q -f qcow2 "${disk}" "${DISK_SIZE_GB}G"
  virt-resize --quiet --expand /dev/sda1 "${cached}" "${disk}" || fail 'virt-resize could not grow the root partition.'
else
  qemu-img convert -q -O qcow2 "${cached}" "${disk}"
fi

# ── scan: the guest's dpkg database, with the host's Trivy and its offline database ─────────
db_age_hours() {
  "${TRIVY}" version --cache-dir "${TRIVY_CACHE_DIR}" --format json |
    node -e 'let s = ""; process.stdin.on("data", (d) => (s += d)).on("end", () => {
      const at = Date.parse(JSON.parse(s).VulnerabilityDB?.UpdatedAt ?? "");
      if (Number.isNaN(at)) process.exit(3);
      console.log(Math.floor((Date.now() - at) / 3600000));
    });'
}
age="$(db_age_hours)" || fail 'Could not read the date of the Trivy database.'
(( age <= MAX_DB_AGE_HOURS )) || fail "The Trivy database is ${age} h old (limit ${MAX_DB_AGE_HOURS} h); download it again."
echo "Trivy database: ${age} h old."

scan() {
  local phase="$1" root="${WORK_DIR}/rootfs-$1"
  step "Scan ${phase}"
  mkdir -p "${root}/var/lib/dpkg/info" "${root}/var/lib/dpkg/updates" "${root}/usr/lib" "${root}/etc"
  guestfish --ro -a "${disk}" -i <<FISH
download /var/lib/dpkg/status ${root}/var/lib/dpkg/status
download /usr/lib/os-release ${root}/usr/lib/os-release
download /etc/lsb-release ${root}/etc/lsb-release
FISH
  [[ -s "${root}/var/lib/dpkg/status" ]] || fail "Could not read the dpkg database of the image (scan ${phase})."
  # Regular files, not the image's symlink: Trivy does not follow symlinks, and it recognises
  # Ubuntu by etc/lsb-release. Without them it finds no OS and reports no vulnerability at all.
  cp "${root}/usr/lib/os-release" "${root}/etc/os-release"
  grep -qx 'VERSION_ID="24.04"' "${root}/usr/lib/os-release" || fail 'The image is not Ubuntu 24.04.'

  "${TRIVY}" rootfs --cache-dir "${TRIVY_CACHE_DIR}" \
    --skip-db-update --skip-java-db-update --offline-scan --disable-telemetry --quiet \
    --scanners vuln --pkg-types os --list-all-pkgs \
    --format json --output "${reports}/scan-${phase}.json" "${root}" || fail "Trivy failed in scan ${phase}."
  # "0 vulnerabilities" counts only when Trivy saw Ubuntu 24.04 and its packages.
  seen="$(node -e 'const r = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
    const os = r.Metadata?.OS ?? {};
    const pkgs = (r.Results ?? []).filter((x) => x.Class === "os-pkgs").reduce((n, x) => n + (x.Packages?.length ?? 0), 0);
    console.log([os.Family || "none", os.Name || "-", pkgs].join(" "));' "${reports}/scan-${phase}.json")" ||
    fail "Could not read the Trivy report of scan ${phase}."
  read -r os_family os_name os_packages <<< "${seen}"
  [[ "${os_family}" == ubuntu && "${os_name}" == 24.04 && "${os_packages:-0}" -gt 0 ]] ||
    fail "Trivy did not recognise the image (OS '${os_family} ${os_name}', ${os_packages:-0} packages); a scan without the OS proves nothing."

  dpkg-query --admindir="${root}/var/lib/dpkg" -W -f='${db:Status-Status}\t${Package}\t${Version}\n' |
    awk -F'\t' '$1 == "installed" { print $2 "\t" $3 }' | LC_ALL=C sort > "${reports}/packages-${phase}.tsv"
  # The newest installed kernel: the template boots it (prune-kernels.sh leaves only that one).
  dpkg-query --admindir="${root}/var/lib/dpkg" -W -f='${db:Status-Status} ${Package}\n' 'linux-image-[0-9]*' |
    awk '$1 == "installed" { sub(/^linux-image-/, "", $2); print $2 }' | sort -V | tail -n1 > "${reports}/kernel-${phase}.txt"
  [[ -s "${reports}/packages-${phase}.tsv" ]] || fail "No installed package was read in scan ${phase}."
  echo "Scan '${phase}': $(wc -l < "${reports}/packages-${phase}.tsv") packages (Trivy: ${os_packages} on ${os_family} ${os_name}), kernel $(cat "${reports}/kernel-${phase}.txt")."
  rm -rf "${root}"
}

scan before

# ── patch: guest/patch.sh and guest/prune-kernels.sh inside the image ───────────────────────
step 'Patch'
cp "${poc}/guest/patch.sh" "${poc}/guest/prune-kernels.sh" "${poc}/guest/seal.sh" "${stage}/ssi-build/"
proxy_args=()
if [[ -n "${APT_PROXY:-}" || -n "${APT_CA_FILE:-}" ]]; then
  {
    [[ -n "${APT_PROXY:-}" ]] && printf 'Acquire::http::Proxy "%s";\nAcquire::https::Proxy "%s";\n' "${APT_PROXY}" "${APT_PROXY}"
    [[ -n "${APT_CA_FILE:-}" ]] && printf 'Acquire::https::CaInfo "/var/tmp/ssi-build/apt-ca.crt";\n'
  } > "${stage}/95ssi-build"
  [[ -n "${APT_CA_FILE:-}" ]] && cp "${APT_CA_FILE}" "${stage}/ssi-build/apt-ca.crt"
  proxy_args=(--upload "${stage}/95ssi-build:/etc/apt/apt.conf.d/95ssi-build")
fi
virt-customize -a "${disk}" "${guest_args[@]}" --network \
  --copy-in "${stage}/ssi-build:/var/tmp" "${proxy_args[@]}" \
  --run-command "env APT_MIRROR='${APT_MIRROR:-}' bash /var/tmp/ssi-build/patch.sh" \
  --run-command 'bash /var/tmp/ssi-build/prune-kernels.sh' ||
  fail 'The patch step failed inside the image (see the apt output above).'

scan after

# ── gate ────────────────────────────────────────────────────────────────────────────────────
step 'Gate'
gate=0
node "${poc}/host/template-report.mjs" report --reports-dir "${reports}" --fail-on-fixable true \
  --template-name "${TEMPLATE_NAME}" --template-version "${TEMPLATE_VERSION}" || gate=$?
if (( gate == 1 )); then
  echo 'The gate refused the template: a vulnerability with a fix is still present (reports/scan-report.md).' >&2
  exit 1
fi
(( gate == 0 )) || fail 'The report could not be written.'

# ── seal, and check the seal on the disk ────────────────────────────────────────────────────
step 'Seal'
virt-customize -a "${disk}" "${guest_args[@]}" --no-network \
  --run-command "env TEMPLATE_NAME='${TEMPLATE_NAME}' TEMPLATE_VERSION='${TEMPLATE_VERSION}' BUILD_ID='${BUILD_ID}' bash /var/tmp/ssi-build/seal.sh" \
  --delete /var/tmp/ssi-build --delete /etc/apt/apt.conf.d/95ssi-build \
  --run-command ': > /etc/machine-id' ||
  fail 'The seal step failed inside the image.'
virt-sparsify --quiet --in-place "${disk}" || fail 'virt-sparsify failed.'

check="$(guestfish --ro -a "${disk}" -i <<'FISH'
glob-expand /etc/ssh/ssh_host_*
echo ---
filesize /etc/machine-id
echo ---
exists /var/tmp/ssi-build
exists /etc/apt/apt.conf.d/95ssi-build
exists /etc/ssi-template-release
FISH
)" || fail 'Could not read the sealed disk.'
expected="$(printf -- '---\n0\n---\nfalse\nfalse\ntrue')"
[[ "${check}" == "${expected}" ]] || fail "The seal is incomplete on the disk (host keys, machine-id, build files or release file):
${check}"
guestfish --ro -a "${disk}" -i cat /etc/ssi-template-release > "${reports}/ssi-template-release.txt"
echo 'Seal verified: no SSH host keys, empty machine-id, no build files, release file present.'

# ── export and manifest ─────────────────────────────────────────────────────────────────────
step 'Export'
SOURCE_DISK="${disk}" OUT_DIR="${out}" TEMPLATE_NAME="${TEMPLATE_NAME}" TEMPLATE_VERSION="${TEMPLATE_VERSION}" \
  BUILD_ID="${BUILD_ID}" OVF_TEMPLATE="${poc}/ovf/ubuntu-2404.ovf.tpl" EXPORT_VHDX=true \
  bash "${poc}/host/export.sh"

first_line() { "$@" 2>/dev/null | head -n1 || true; }
tools="$(node -e 'console.log(JSON.stringify(Object.fromEntries(process.argv.slice(1).map((pair) => pair.split("=")))))' \
  "libguestfs=$(first_line virt-customize --version)" \
  "qemu-img=$(first_line qemu-img --version)" \
  "trivy=$("${TRIVY}" version --format json | node -e 'let s="";process.stdin.on("data",(d)=>(s+=d)).on("end",()=>console.log(JSON.parse(s).Version))')" \
  "trivyDbUpdatedAt=$("${TRIVY}" version --cache-dir "${TRIVY_CACHE_DIR}" --format json | node -e 'let s="";process.stdin.on("data",(d)=>(s+=d)).on("end",()=>console.log(JSON.parse(s).VulnerabilityDB.UpdatedAt))')")"
node "${poc}/host/template-report.mjs" manifest --artifacts-dir "${out}" --report "${reports}/scan-report.json" \
  --out "${out}/template-manifest.json" --template-name "${TEMPLATE_NAME}" --template-version "${TEMPLATE_VERSION}" \
  --build-id "${BUILD_ID}" --base-image-url "${BASE_IMAGE_URL}" --base-image-sha256 "${BASE_IMAGE_SHA256}" \
  --tools "${tools}"

rm -f "${disk}"
rm -rf "${stage}" "${TMPDIR}"
step "Done: ${TEMPLATE_NAME} ${TEMPLATE_VERSION}"
ls -l "${out}"
