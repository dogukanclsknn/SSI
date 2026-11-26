#!/usr/bin/env bash
# Waits until cloud-init has finished its first boot, so nothing it still does (apt, users,
# SSH keys) races the scan and the upgrade. Runs as root inside the build VM.
set -euo pipefail

set +e
cloud-init status --wait >/dev/null
status=$?
set -e
# 0 = done, 2 = done with recoverable warnings (cloud-init 23.4+); anything else is a failure.
if [[ "${status}" -ne 0 && "${status}" -ne 2 ]]; then
  echo "cloud-init did not finish cleanly (exit ${status}):" >&2
  cloud-init status --long >&2 || true
  exit 1
fi
os_name="$(sed -n 's/^PRETTY_NAME="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' /etc/os-release)"
echo "cloud-init finished (exit ${status}); OS: ${os_name}, kernel $(uname -r)."
