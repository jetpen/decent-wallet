# Desktop wallet-container CLI

This is the optional Linux desktop/Podman target for Issue #18. It packages the existing Python wallet core; it does not fork the cryptography or wallet-container implementation. The wallet artifact is the encrypted `.dw` file. The OCI image is only the runtime used to execute the desktop CLI.

The CLI provides explicit container operations:

- `create WALLET_PATH` creates a new v2 signing wallet using the OS-backed CSRNG.
- `import WALLET_PATH BACKUP_PATH` authenticates and imports the exact encrypted bytes to a new destination.
- `export WALLET_PATH BACKUP_PATH` unlocks the wallet and writes its exact encrypted bytes to a new destination.
- `migrate WALLET_PATH` explicitly authenticates and migrates the immediately preceding v1 format to v2 in place.

Every command locks its in-memory wallet session before exiting. Passwords are requested with hidden terminal input. The CLI refuses password entry when stdin is not a terminal and treats `getpass` echo-fallback warnings as errors. Passwords are never accepted as command arguments or environment variables. Output is limited to generic status/error categories; wallet payloads, keys, backup bytes, and raw filesystem exception values are not printed.

Create, import, and export never overwrite an existing destination. Export and import operate on the encrypted bytes; no Registry state is read or changed. The CLI does not provide automatic transfer or synchronization. Use a caller-selected host directory and an external user-controlled transfer method for backups. Container v1 files must be migrated explicitly; direct import accepts v2 only.

## Build and conformance

From the repository root:

```sh
podman build -f platforms/desktop-wallet/Containerfile -t decent-wallet-desktop:local .
CONTAINER_RUNTIME=podman platforms/desktop-wallet/verify-container.sh
```

The image installs dependencies through `uv sync --locked` from the repository's `uv.lock`; the `registry` extra pins the compatible `decent-registry` source revision for the desktop API. The verification script requires rootless Podman by default. It builds the `conformance` stage and runs the complete Python test suite, including the shared v2 known-answer vector and desktop CLI lifecycle/fault tests, with networking disabled, a read-only root filesystem, no Linux capabilities, and a temporary `/tmp` filesystem. It builds a temporary `runtime-conformance` stage from the final runtime OS image and runs the direct-DHT transport and operation-5 rotation integration cases against loopback-only peers with the final runtime libraries, covering confirmed publication, definitive expiry rejection, and ambiguous-write recovery. Finally it builds the default final runtime image and smoke-tests the installed CLI and public `RegistryTransport` import with networking disabled. Set `CONTAINER_RUNTIME=docker` only if a Docker-compatible daemon is available; that path does not prove rootless Podman behavior.

## Rootless Podman use

Create a private host directory and build the image once:

```sh
install -d -m 700 "$HOME/.local/share/decent-wallet"
podman build -f platforms/desktop-wallet/Containerfile -t decent-wallet-desktop:local .
```

Run each command interactively, map the invoking UID/GID into the container, and mount only the selected wallet directory:

```sh
podman run --rm -it \
  --network=none --read-only --cap-drop=all \
  --security-opt=no-new-privileges --userns=keep-id \
  --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  -v "$HOME/.local/share/decent-wallet:/wallet:rw,Z" \
  decent-wallet-desktop:local create /wallet/main.dw
```

Use `export /wallet/main.dw /wallet/backup.dw`, `import /wallet/restored.dw /wallet/backup.dw`, or `migrate /wallet/main.dw` in the same invocation form. `-it` is required for hidden password prompts. On systems without SELinux, omit the `,Z` volume suffix. The destination for `create`, `import`, or `export` must not already exist. Keep the mounted directory private and never mount a general-purpose synchronized folder for automatic backup.

For Python integration on the host or from the package installed in the Podman runtime, use the public `decent_wallet` API. This API is the desktop/Podman surface for Issue #18 rotation parity and reuses the Python core's wallet and Registry-adapter contracts, as proposed in [ADR-0005](../../docs/adr/0005-desktop-rotation-api-boundary.md). In this repository, `uv sync --locked --extra registry` installs the pinned `decent-registry` dependency; the packaged runtime includes the same extra. `RegistryTransport` is exported as `decent_wallet.RegistryTransport`; `supports_owner_key_rotation` defaults to false and may be enabled only when every target peer is pinned to a compatible operation-5 validator. Applications must use persistent transport storage and inject a durable replay-nonce store; the adapter's `authenticated_origin` remains a trusted host assertion. The CLI itself remains limited to container lifecycle commands: it is not a GUI, consent interface, or Registry/DHT transport and has no rotation subcommand. This package does not define a production Registry deployment or runtime configuration, so no production endpoint or acceptance is implied.
