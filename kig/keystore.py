"""Where a private key lives, behind one small interface.

`KeyStore` is the seam for hardware-backed storage (an HSM, a cloud KMS, an OS keychain): an
implementation only has to store and return the secret bytes under a name. `FileKeyStore` is
the one we ship: a file per key, mode 0600, optionally sealed with the passphrase vault.
`MemoryKeyStore` is for tests. We ship no HSM or KMS driver and do not claim hardware protection.
With any store the service process still holds the key in memory while it runs.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Protocol

from . import vault

log = logging.getLogger(__name__)
_NAME = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")


class KeyStore(Protocol):
    def get(self, name: str) -> bytes | None: ...
    def put(self, name: str, secret: bytes) -> None: ...


def _check(name: str) -> str:
    if not _NAME.fullmatch(name):
        raise ValueError("bad key name")
    return name


class MemoryKeyStore:
    def __init__(self) -> None:
        self._d: dict[str, bytes] = {}

    def get(self, name: str) -> bytes | None:
        return self._d.get(_check(name))

    def put(self, name: str, secret: bytes) -> None:
        self._d[_check(name)] = bytes(secret)


class FileKeyStore:
    def __init__(self, directory: str | Path, passphrase: str | None = None) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.passphrase = passphrase if passphrase is not None else vault.passphrase_from_env()

    def _path(self, name: str) -> Path:
        return self.dir / f"{_check(name)}.key"

    def get(self, name: str) -> bytes | None:
        p = self._path(name)
        if not p.exists():
            return None
        raw = p.read_bytes()
        return vault.open_(raw, self.passphrase, f"prism/keystore/{name}") if vault.is_sealed(raw) else raw

    def put(self, name: str, secret: bytes) -> None:
        if not self.passphrase:
            log.warning("FileKeyStore: no passphrase set, key %r is stored unencrypted (file mode 0600 only)", name)
        blob = vault.seal(secret, self.passphrase, f"prism/keystore/{name}") if self.passphrase else secret
        vault.write_atomic(self._path(name), blob, 0o600)
