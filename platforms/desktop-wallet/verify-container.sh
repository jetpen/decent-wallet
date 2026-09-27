#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repository_root"

runtime=${CONTAINER_RUNTIME:-podman}
if ! command -v "$runtime" >/dev/null 2>&1; then
  printf '%s\n' "container runtime not found: set CONTAINER_RUNTIME to podman or docker" >&2
  exit 127
fi

containerfile=platforms/desktop-wallet/Containerfile
conformance_image=decent-wallet-desktop-conformance:local
runtime_image=decent-wallet-desktop:smoke

"$runtime" build \
  --file "$containerfile" \
  --target conformance \
  --tag "$conformance_image" \
  .
"$runtime" run --rm \
  --network=none \
  --read-only \
  --cap-drop=all \
  --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  "$conformance_image"

"$runtime" build \
  --file "$containerfile" \
  --target runtime \
  --tag "$runtime_image" \
  .
"$runtime" run --rm \
  --network=none \
  --read-only \
  --cap-drop=all \
  --security-opt=no-new-privileges \
  "$runtime_image" \
  --help
