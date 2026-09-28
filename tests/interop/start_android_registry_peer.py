from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

import trio
from decent_registry.dht.libp2p_dht import Libp2pKadDHT
from decent_registry.durable_store import LMDBDatastore


REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = REPO_ROOT / "tests" / "vectors" / "identity-owner-key-rotation-legacy.json"


def load_fixture() -> tuple[str, bytes]:
    vector = json.loads(FIXTURE.read_text(encoding="utf-8"))
    owner_name = bytes.fromhex(vector["owner_name_utf8_hex"])
    identity_key = hashlib.sha256(owner_name).hexdigest()
    predecessor = bytes.fromhex(vector["predecessor_envelope_cbor_hex"])
    return identity_key, predecessor


async def main() -> None:
    identity_key, predecessor = load_fixture()
    scratch = Path(os.environ.get("TMPDIR", Path.home() / ".cache" / "decent-wallet"))
    scratch.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="android-registry-interop-", dir=scratch) as root:
        store_path = Path(root) / "accepted.lmdb"
        async with Libp2pKadDHT(
            listen="/ip4/127.0.0.1/tcp/0",
            durable_store=LMDBDatastore(path=store_path),
        ) as registry:
            await registry.put_signed_identity_record(identity_key, predecessor)
            peer = registry.get_listen_multiaddr()
            if "/p2p/" not in peer:
                peer = f"{peer}/p2p/{registry.host.get_id().to_string()}"
            print(f"READY\t{peer}", flush=True)
            await trio.sleep_forever()


if __name__ == "__main__":
    trio.run(main)
