from decent_wallet import RegistryTransport
from decent_wallet.registry_transport import RegistryTransport as ModuleRegistryTransport


def test_registry_transport_is_exported_from_public_package() -> None:
    assert RegistryTransport is ModuleRegistryTransport
