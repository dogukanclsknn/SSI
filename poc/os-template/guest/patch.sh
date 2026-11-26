#!/usr/bin/env bash
# Brings every package up to date and adds the guest agents both hypervisor families expect
# (open-vm-tools for VMware, qemu-guest-agent for Proxmox/KVM). Runs as root inside the build VM.
#
# APT_MIRROR (optional): an internal Ubuntu mirror or snapshot (http(s)://host/path). When set,
# every package comes from it instead of the public archive, which is how the internal package
# repository of the reference topology plugs in without changing this script.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

if [[ -n "${APT_MIRROR:-}" ]]; then
  if [[ ! "${APT_MIRROR}" =~ ^https?://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~/-]*)?$ ]]; then
    echo 'APT_MIRROR must be an http(s) URL without credentials or query.' >&2
    exit 2
  fi
  sources=/etc/apt/sources.list.d/ubuntu.sources
  if [[ ! -f "${sources}" ]]; then
    echo "${sources} not found; cannot point apt at the mirror." >&2
    exit 2
  fi
  sed -i -E "s#^URIs: .*#URIs: ${APT_MIRROR}#" "${sources}"
  echo "apt uses the mirror ${APT_MIRROR}."
fi

apt_get() {
  apt-get -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
    -o APT::Get::Assume-Yes=true -o Acquire::Retries=3 "$@"
}

apt_get update
apt_get full-upgrade
apt_get install open-vm-tools qemu-guest-agent
apt_get autoremove --purge

if [[ -f /var/run/reboot-required ]]; then
  echo 'A reboot is required (new kernel or core library); the next step reboots before the second scan.'
fi
