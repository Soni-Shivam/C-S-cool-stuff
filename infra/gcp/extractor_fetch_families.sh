#!/usr/bin/env bash
# Source family-labelled detonation candidates. Runs ON THE EXTRACTOR VM.
#
#   extractor_fetch_families.sh <out.csv> <family> [family ...]
#
# The MalwareBazaar key is not on disk anywhere on this VM — it was passed to the
# extraction units through systemd and lives only in their process environment. Reading
# it from /proc keeps it that way: no key file is created, so none can be left behind.
#
# `nice`, because the extraction shards own this box and a sourcing run must not cost
# them throughput.
set -euo pipefail

# `gcloud compute ssh --command` runs a non-login shell, which never sources the
# profile that puts uv on PATH. Without this the run dies with "uv: No such file".
export PATH="${HOME}/.local/bin:${PATH}"

OUT="${1:?usage: extractor_fetch_families.sh <out.csv> <family> [family ...]}"
shift
[[ $# -ge 1 ]] && : || { echo "at least one family required" >&2; exit 2; }

cd "${HOME}/CyberShield"

PID=$(systemctl --user show drishti-mb-0.service -p MainPID --value)
KEY=$(sudo tr '\0' '\n' < "/proc/${PID}/environ" | sed -n 's/^DRISHTI_MALWAREBAZAAR_API_KEY=//p')
[[ -n "${KEY}" ]] || { echo "MalwareBazaar key not found in the extraction unit's environment" >&2; exit 1; }

ARGS=()
for family in "$@"; do ARGS+=(--family "${family}"); done

DRISHTI_MALWAREBAZAAR_API_KEY="${KEY}" nice -n 10 \
  uv run python scripts/fetch_detonation_candidates.py \
  "${ARGS[@]}" \
  --per-family "${PER_FAMILY:-5}" \
  --candidates "${CANDIDATES:-30}" \
  --out "${OUT}" \
  --i-am-the-extractor-vm
