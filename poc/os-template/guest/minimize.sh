#!/usr/bin/env bash
# Removes the packages of the template profile (docs/os-template-poc.md, "Template profili").
# apt simulates the removal first; if anything protected would go, even as a side effect,
# nothing is removed and the build stops. Runs as root inside the build VM, after the upgrade
# and before the second scan, so the report shows what the removal closed.
#
#   REMOVE_LIST      file, one package name per line (the profile's list, validated on the host)
#   PROTECTED_LIST   file, protected patterns (profiles/protected-packages.txt)
#   SCAN_DIR         results go to SCAN_DIR/out: minimize-plan.tsv, minimize-removed.tsv,
#                    minimize-skipped.txt
#   MINIMIZE_DRY_RUN 1 = simulate and write the plan only
# Exit codes: 0 done (or nothing to do), 2 invalid input, 3 refused (protected package).
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

SCAN_DIR="${SCAN_DIR:-/var/tmp/ssi-scan}"
OUT_DIR="${SCAN_DIR}/out"
fail() {
  echo "minimize: $*" >&2
  exit 2
}
[[ -f "${REMOVE_LIST:-}" ]] || fail 'REMOVE_LIST is not a file.'
[[ -f "${PROTECTED_LIST:-}" ]] || fail 'PROTECTED_LIST is not a file.'
mkdir -p "${OUT_DIR}"

mapfile -t patterns < <(sed -e 's/#.*//' -e 's/[[:space:]]//g' "${PROTECTED_LIST}" | grep -v '^$' || true)
for pattern in "${patterns[@]}"; do
  [[ "${pattern}" =~ ^[a-z0-9*][a-z0-9+.*-]*$ ]] || fail "invalid protected pattern: ${pattern}"
done

# Why a package may not go, or nothing.
protection_of() {
  local name="$1" pattern fields
  for pattern in "${patterns[@]}"; do
    # shellcheck disable=SC2053  # the pattern is a glob on purpose
    if [[ "${name}" == ${pattern} ]]; then
      echo "protected (${pattern})"
      return
    fi
  done
  fields="$(dpkg-query -W -f='${Essential} ${Priority}' "${name}" 2>/dev/null || true)"
  case "${fields}" in
    'yes '*) echo 'essential package' ;;
    *' required') echo 'required-priority package' ;;
  esac
}

requested=()
skipped=()
while IFS= read -r line || [[ -n "${line}" ]]; do
  name="$(printf '%s' "${line}" | tr -d '[:space:]')"
  [[ -z "${name}" ]] && continue
  [[ "${name}" =~ ^[a-z0-9][a-z0-9+.-]+$ ]] || fail "not a package name: ${name}"
  if [[ "$(dpkg-query -W -f='${db:Status-Status}' "${name}" 2>/dev/null || true)" == installed ]]; then
    requested+=("${name}")
  else
    skipped+=("${name}")
  fi
done < "${REMOVE_LIST}"

printf '%s\n' "${skipped[@]}" | sed '/^$/d' > "${OUT_DIR}/minimize-skipped.txt"
: > "${OUT_DIR}/minimize-plan.tsv"
: > "${OUT_DIR}/minimize-removed.tsv"
if (( ${#requested[@]} == 0 )); then
  echo "Nothing to remove (${#skipped[@]} listed package(s) not installed)."
  exit 0
fi

blocked=()
# A requested package that is itself protected is refused before apt is even asked.
for name in "${requested[@]}"; do
  why="$(protection_of "${name}")"
  if [[ -n "${why}" ]]; then blocked+=("${name}: ${why}"); fi
done
if (( ${#blocked[@]} > 0 )); then
  echo 'minimize: refused, the profile lists protected packages:' >&2
  printf '  %s\n' "${blocked[@]}" >&2
  exit 3
fi

# What apt would really remove, including packages only the removed ones needed. When apt
# cannot resolve the removal (e.g. an essential package), it refuses, and so does this script.
simulation="$(mktemp)"
trap 'rm -f "${simulation}"' EXIT
if ! LC_ALL=C apt-get -s -o Debug::NoLocking=1 --autoremove purge "${requested[@]}" > "${simulation}" 2>&1; then
  echo 'minimize: refused, apt cannot remove this selection without breaking packages the system needs:' >&2
  grep -E '^(E|W):' "${simulation}" | head -n 20 >&2 || true
  exit 3
fi
mapfile -t plan < <(sed -n -E 's/^(Purg|Remv) ([a-z0-9][a-z0-9+.-]*)(:[a-z0-9]+)? \[([^]]*)\].*/\2\t\4/p' "${simulation}" | LC_ALL=C sort -u)
for entry in "${plan[@]}"; do
  name="${entry%%$'\t'*}"
  reason="requested"
  printf '%s\n' "${requested[@]}" | grep -qx -- "${name}" || reason="dependency"
  printf '%s\t%s\n' "${entry}" "${reason}" >> "${OUT_DIR}/minimize-plan.tsv"
  why="$(protection_of "${name}")"
  if [[ -n "${why}" ]]; then blocked+=("${name}: ${why}"); fi
done
chmod 0644 "${OUT_DIR}"/minimize-*

if (( ${#blocked[@]} > 0 )); then
  echo 'minimize: refused, the removal would take protected packages along:' >&2
  printf '  %s\n' "${blocked[@]}" >&2
  exit 3
fi
echo "Plan: ${#requested[@]} requested, ${#plan[@]} package(s) in total (see minimize-plan.tsv)."
if [[ "${MINIMIZE_DRY_RUN:-0}" == 1 ]]; then
  echo 'Dry run: nothing was removed.'
  exit 0
fi

apt-get -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -y \
  --autoremove purge "${requested[@]}"

for entry in "${plan[@]}"; do
  name="${entry%%$'\t'*}"
  if [[ "$(dpkg-query -W -f='${db:Status-Status}' "${name}" 2>/dev/null || true)" == installed ]]; then
    echo "minimize: ${name} is still installed after the removal." >&2
    exit 2
  fi
  printf '%s\n' "${entry}" >> "${OUT_DIR}/minimize-removed.tsv"
done
echo "Removed ${#plan[@]} package(s)."
