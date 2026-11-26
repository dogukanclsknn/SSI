#!/usr/bin/env bash
# Keeps only the newest installed kernel. The offline build (linux/build-ubuntu-template.sh)
# never boots the template, so apt has no "running kernel" of the guest to protect and the
# kernels the upgrade replaced would stay installed: the second scan would report their fixed
# CVEs as still open, and every VM made from the template would carry them.
# Runs as root inside the guest, after guest/patch.sh. Removes only versioned kernel packages
# (image, modules, modules-extra, headers) of the older versions; the meta packages stay.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

installed_versions() {
  dpkg-query -W -f='${db:Status-Status} ${Package}\n' 'linux-image-[0-9]*' 2>/dev/null |
    awk '$1 == "installed" { sub(/^linux-image-/, "", $2); print $2 }' | sort -V
}

mapfile -t versions < <(installed_versions)
if (( ${#versions[@]} == 0 )); then
  echo 'prune-kernels: no versioned kernel is installed; nothing to keep.' >&2
  exit 2
fi
newest="${versions[-1]}"
echo "Keeping kernel ${newest}."

old=()
for version in "${versions[@]}"; do
  [[ "${version}" == "${newest}" ]] && continue
  [[ "${version}" =~ ^[0-9][0-9a-z.+-]*$ ]] || { echo "prune-kernels: unexpected version ${version}" >&2; exit 2; }
  # Only the packages of this version that are really installed.
  while read -r status name; do
    [[ "${status}" == installed ]] && old+=("${name}")
  done < <(dpkg-query -W -f='${db:Status-Status} ${Package}\n' \
    "linux-image-${version}" "linux-modules-${version}" "linux-modules-extra-${version}" \
    "linux-headers-${version}" 2>/dev/null || true)
done

if (( ${#old[@]} == 0 )); then
  echo 'No older kernel to remove.'
  exit 0
fi
echo "Removing older kernel packages: ${old[*]}"
apt-get -o APT::Get::Assume-Yes=true purge "${old[@]}"
apt-get -o APT::Get::Assume-Yes=true autoremove --purge

mapfile -t left < <(installed_versions)
if [[ "${#left[@]}" -ne 1 || "${left[0]}" != "${newest}" ]]; then
  echo "prune-kernels: kernels still installed: ${left[*]}" >&2
  exit 3
fi
