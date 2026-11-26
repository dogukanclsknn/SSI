#!/usr/bin/env bash
# SSI OS template PoC — signs files with cosign (sign-blob) and verifies every signature before
# reporting success. Same key format and secret names as the supply-chain sign pipeline:
#   COSIGN_PRIVATE_KEY, COSIGN_PUBLIC_KEY  base64 of the PEM files
#   COSIGN_PASSWORD                        password of the private key
# Writes <file>.sig next to each file, cosign.pub into the directory of the first file and the key
# ID (sha256 of the public key) to KEY_ID_FILE when set. The key lives only in a 0700 temporary
# directory that is removed on exit.
#
# Usage: COSIGN=/path/to/cosign sign.sh FILE...
set -euo pipefail

COSIGN="${COSIGN:-cosign}"
fail() {
  echo "sign: $*" >&2
  exit 2
}
(( $# > 0 )) || fail 'no file to sign.'
for name in COSIGN_PRIVATE_KEY COSIGN_PUBLIC_KEY COSIGN_PASSWORD; do
  value="${!name:-}"
  # Azure DevOps passes an undefined variable as the literal text $(NAME).
  # shellcheck disable=SC2016
  [[ -n "${value}" && "${value}" != '$('* ]] || fail "${name} is not set."
done
for file in "$@"; do [[ -f "${file}" ]] || fail "${file} not found."; done

KEY_DIR="$(mktemp -d)"
chmod 700 "${KEY_DIR}"
trap 'rm -rf "${KEY_DIR}"' EXIT
printf '%s' "${COSIGN_PRIVATE_KEY}" | base64 -d > "${KEY_DIR}/cosign.key" 2>/dev/null || fail 'COSIGN_PRIVATE_KEY is not valid base64.'
printf '%s' "${COSIGN_PUBLIC_KEY}" | base64 -d > "${KEY_DIR}/cosign.pub" 2>/dev/null || fail 'COSIGN_PUBLIC_KEY is not valid base64.'
chmod 600 "${KEY_DIR}/cosign.key"
"${COSIGN}" public-key --key "${KEY_DIR}/cosign.key" > "${KEY_DIR}/derived.pub" 2>/dev/null ||
  fail 'The private key could not be opened (wrong COSIGN_PASSWORD or not a cosign key).'
cmp -s <(tr -d '\r' < "${KEY_DIR}/derived.pub") <(tr -d '\r' < "${KEY_DIR}/cosign.pub") ||
  fail 'COSIGN_PUBLIC_KEY does not belong to COSIGN_PRIVATE_KEY.'

for file in "$@"; do
  # --tlog-upload=false: the signature stays inside the organisation (no public transparency log).
  "${COSIGN}" sign-blob --yes --key "${KEY_DIR}/cosign.key" --tlog-upload=false \
    --output-signature "${file}.sig" "${file}" > /dev/null 2>&1 || fail "signing ${file} failed."
  "${COSIGN}" verify-blob --key "${KEY_DIR}/cosign.pub" --insecure-ignore-tlog=true \
    --signature "${file}.sig" "${file}" > /dev/null 2>&1 || fail "the signature of ${file} does not verify."
  echo "Signed and verified: $(basename "${file}")"
done

cp "${KEY_DIR}/cosign.pub" "$(dirname "$1")/cosign.pub"
key_id="cosign (sha256:$(sha256sum "${KEY_DIR}/cosign.pub" | cut -c1-12))"
if [[ -n "${KEY_ID_FILE:-}" ]]; then printf '%s\n' "${key_id}" > "${KEY_ID_FILE}"; fi
echo "Key: ${key_id}"
