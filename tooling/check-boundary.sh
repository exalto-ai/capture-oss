#!/usr/bin/env sh
set -eu

runtime_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec python3 "$runtime_dir/tooling/check_boundary.py"
