#!/usr/bin/env bash
set -euo pipefail

echo "ABORT: in-place detonator setup is retired." >&2
echo "Build the immutable tool image with infra/m3/build_tools_image.sh and launch" >&2
echo "the no-egress runtime with infra/m3/terraform/runtime instead." >&2
exit 2
