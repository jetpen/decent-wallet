#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repository_root"

runtime=${CONTAINER_RUNTIME:-podman}
if ! command -v "$runtime" >/dev/null 2>&1; then
  printf '%s\n' "container runtime not found: set CONTAINER_RUNTIME to podman or docker" >&2
  exit 127
fi
if [ "$runtime" = "podman" ]; then
  rootless=$("$runtime" info --format '{{.Host.Security.Rootless}}')
  if [ "$rootless" != "true" ]; then
    printf '%s\n' "Podman must be running rootless for desktop rotation verification" >&2
    exit 2
  fi
fi

containerfile=platforms/desktop-wallet/Containerfile
conformance_image=decent-wallet-desktop-conformance:local
runtime_conformance_image=decent-wallet-desktop-runtime-conformance:local
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
  --target runtime-conformance \
  --tag "$runtime_conformance_image" \
  .
"$runtime" run --rm \
  --network=none \
  --read-only \
  --cap-drop=all \
  --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  "$runtime_conformance_image"

"$runtime" build \
  --file "$containerfile" \
  --tag "$runtime_image" \
  .
"$runtime" run --rm \
  --network=none \
  --read-only \
  --cap-drop=all \
  --security-opt=no-new-privileges \
  "$runtime_image" \
  --help

"$runtime" run --rm \
  --network=none \
  --read-only \
  --cap-drop=all \
  --security-opt=no-new-privileges \
  --entrypoint /opt/venv/bin/python \
  "$runtime_image" \
  -c 'import decent_registry; from decent_wallet import RegistryTransport; assert RegistryTransport.__name__ == "RegistryTransport"'
