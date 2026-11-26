#!/usr/bin/env bash
# SSI OS template PoC — turns the sealed template disk into the two delivery formats
# (docs/os-template-poc.md) and writes their checksums:
#   <name>-<version>.qcow2   Proxmox VE / KVM (compressed qcow2)
#   <name>-<version>.ova     VMware vSphere (OVF descriptor + streamOptimized VMDK + manifest)
#   <name>-<version>.vhdx    Hyper-V (dynamic VHDX), only with EXPORT_VHDX=true
#   SHA256SUMS               sha256sum -c format
# Every format is converted from the same scanned disk, so the scan evidence covers both.
#
# Environment: SOURCE_DISK, OUT_DIR (created; must not hold earlier artifacts), TEMPLATE_NAME,
# TEMPLATE_VERSION, BUILD_ID, OVF_TEMPLATE; optional CPUS (2), MEMORY_MB (2048), EXPORT_VHDX (false).
set -euo pipefail

: "${SOURCE_DISK:?}" "${OUT_DIR:?}" "${TEMPLATE_NAME:?}" "${TEMPLATE_VERSION:?}" "${BUILD_ID:?}" "${OVF_TEMPLATE:?}"
CPUS="${CPUS:-2}"
MEMORY_MB="${MEMORY_MB:-2048}"
EXPORT_VHDX="${EXPORT_VHDX:-false}"

fail() {
  echo "export: $*" >&2
  exit 2
}
[[ "${TEMPLATE_NAME}" =~ ^[a-z0-9][a-z0-9-]{1,62}$ ]] || fail 'TEMPLATE_NAME is invalid.'
[[ "${TEMPLATE_VERSION}" =~ ^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$ ]] || fail 'TEMPLATE_VERSION is invalid.'
[[ "${BUILD_ID}" =~ ^[0-9A-Za-z._-]{1,64}$ ]] || fail 'BUILD_ID is invalid.'
[[ "${CPUS}" =~ ^[1-9][0-9]?$ && "${MEMORY_MB}" =~ ^[1-9][0-9]{2,6}$ ]] || fail 'CPUS or MEMORY_MB is invalid.'
[[ "${EXPORT_VHDX}" == true || "${EXPORT_VHDX}" == false ]] || fail 'EXPORT_VHDX must be true or false.'
[[ -f "${SOURCE_DISK}" && -f "${OVF_TEMPLATE}" ]] || fail 'SOURCE_DISK or OVF_TEMPLATE not found.'
for tool in qemu-img sha256sum tar node; do command -v "${tool}" >/dev/null || fail "${tool} is required."; done

mkdir -p "${OUT_DIR}"
if compgen -G "${OUT_DIR}/*.qcow2" >/dev/null || compgen -G "${OUT_DIR}/*.ova" >/dev/null ||
  compgen -G "${OUT_DIR}/*.vhdx" >/dev/null; then
  fail "${OUT_DIR} already holds artifacts; use an empty directory."
fi
WORK="$(mktemp -d "${OUT_DIR}/.export.XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT

base="${TEMPLATE_NAME}-${TEMPLATE_VERSION}"
qemu-img check -q "${SOURCE_DISK}" || fail 'The source disk does not pass qemu-img check.'
# The top-level virtual-size (nested entries describe the image file itself, not the disk).
capacity="$(qemu-img info --output=json "${SOURCE_DISK}" |
  node -e 'let s = ""; process.stdin.on("data", (d) => (s += d)).on("end", () => console.log(JSON.parse(s)["virtual-size"]));')"
[[ "${capacity}" =~ ^[0-9]+$ ]] || fail 'Could not read the virtual size of the source disk.'

echo "Converting to qcow2 (compressed) …"
qemu-img convert -q -O qcow2 -c -o compat=1.1 "${SOURCE_DISK}" "${OUT_DIR}/${base}.qcow2"

echo "Converting to a streamOptimized VMDK and packing the OVA …"
vmdk="${base}-disk1.vmdk"
qemu-img convert -q -O vmdk -o subformat=streamOptimized,adapter_type=lsilogic "${SOURCE_DISK}" "${WORK}/${vmdk}"
vmdk_size="$(stat -c %s "${WORK}/${vmdk}")"
# ustar members are limited to 8 GiB; a bigger disk needs another archive format.
(( vmdk_size < 8589934592 )) || fail 'The VMDK is larger than 8 GiB; it cannot be stored in an ustar OVA.'

sed -e "s|@NAME@|${TEMPLATE_NAME}|g" -e "s|@VERSION@|${TEMPLATE_VERSION}|g" -e "s|@BUILD_ID@|${BUILD_ID}|g" \
  -e "s|@VMDK_FILE@|${vmdk}|g" -e "s|@VMDK_SIZE@|${vmdk_size}|g" -e "s|@CAPACITY_BYTES@|${capacity}|g" \
  -e "s|@CPUS@|${CPUS}|g" -e "s|@MEMORY_MB@|${MEMORY_MB}|g" \
  "${OVF_TEMPLATE}" > "${WORK}/${base}.ovf"
if grep -q '@[A-Z_]*@' "${WORK}/${base}.ovf"; then fail 'The OVF descriptor still has unfilled placeholders.'; fi
if command -v xmllint >/dev/null; then xmllint --noout "${WORK}/${base}.ovf" || fail 'The OVF descriptor is not well-formed XML.'; fi

# OVF manifest: SHA-256 of the descriptor and the disk (VMware checks it on import).
(
  cd "${WORK}"
  for file in "${base}.ovf" "${vmdk}"; do
    printf 'SHA256(%s)= %s\n' "${file}" "$(sha256sum "${file}" | cut -d' ' -f1)"
  done
) > "${WORK}/${base}.mf"
# The descriptor must be the first member of an OVA.
tar -C "${WORK}" --format=ustar --owner=0 --group=0 --numeric-owner -cf "${OUT_DIR}/${base}.ova" \
  "${base}.ovf" "${base}.mf" "${vmdk}"
[[ "$(tar -tf "${OUT_DIR}/${base}.ova" | head -n1)" == "${base}.ovf" ]] || fail 'The OVA does not start with its descriptor.'

qemu-img check -q "${OUT_DIR}/${base}.qcow2" || fail 'The exported qcow2 does not pass qemu-img check.'
files=("${base}.qcow2" "${base}.ova")
if [[ "${EXPORT_VHDX}" == true ]]; then
  echo "Converting to a dynamic VHDX (Hyper-V) …"
  qemu-img convert -q -O vhdx -o subformat=dynamic "${SOURCE_DISK}" "${OUT_DIR}/${base}.vhdx"
  qemu-img check -q "${OUT_DIR}/${base}.vhdx" || fail 'The exported VHDX does not pass qemu-img check.'
  files+=("${base}.vhdx")
fi
(cd "${OUT_DIR}" && sha256sum "${files[@]}" > SHA256SUMS && sha256sum -c --quiet SHA256SUMS)

echo "Exported:"
for file in "${files[@]}"; do
  printf '  %s  %s bytes\n' "${file}" "$(stat -c %s "${OUT_DIR}/${file}")"
done
