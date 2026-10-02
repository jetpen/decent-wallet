from __future__ import annotations

import argparse
import signal
import sys
from collections.abc import Sequence

import trio


def announce_address(listen_multiaddr: str, peer_id: str) -> str:
    components = listen_multiaddr.split("/p2p/")
    if len(components) == 1:
        return f"{listen_multiaddr}/p2p/{peer_id}"
    if len(components) == 2 and components[1] == peer_id:
        return listen_multiaddr
    raise ValueError("listen multiaddr has a duplicate or mismatched peer id")


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one isolated Registry DHT peer")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--datastore-path", required=True)
    parser.add_argument("--bootstrap", action="append", default=[])
    return parser.parse_args(argv)


async def _run_peer(args: argparse.Namespace) -> None:
    from decent_registry.dht.libp2p_dht import DHTMode, Libp2pKadDHT
    from decent_registry.durable_store import LMDBDatastore
    from libp2p.peer.peerinfo import info_from_p2p_addr
    from multiaddr import Multiaddr

    listen = f"/ip4/{args.host}/tcp/{args.port}"
    datastore = LMDBDatastore(path=args.datastore_path)
    async with Libp2pKadDHT(listen=listen, durable_store=datastore) as peer:
        peer_id = peer.host.get_id().to_string()
        print(
            f"[BOOTSTRAP] {announce_address(peer.get_listen_multiaddr(), peer_id)}",
            flush=True,
        )
        for address in args.bootstrap:
            peer_info = info_from_p2p_addr(Multiaddr(address))
            await peer.bootstrap(address)
            await peer.dht.add_peer(peer_info.peer_id)
        with trio.open_signal_receiver(signal.SIGINT, signal.SIGTERM) as signals:
            async for _signum in signals:
                break


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        trio.run(_run_peer, args)
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        error_type = type(exc).__name__
        if not error_type.isidentifier() or len(error_type) > 40:
            error_type = "OtherError"
        print(f"REGISTRY_PEER_ERROR\t{error_type}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
