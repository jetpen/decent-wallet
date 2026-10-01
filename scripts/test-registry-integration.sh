#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository_root"

registry_path=${DECENT_REGISTRY_PATH:-../decent-registry}
if [ ! -f "$registry_path/pyproject.toml" ]; then
    printf '%s\n' "decent-registry checkout not found: $registry_path" >&2
    printf '%s\n' "set DECENT_REGISTRY_PATH to a checkout at a compatible provider revision" >&2
    exit 2
fi

uv run --locked --extra test \
    --with-editable "$registry_path" \
    pytest -m registry_integration \
        tests/test_registry_transport_integration.py \
        tests/test_portable_latch_registry_integration.py
