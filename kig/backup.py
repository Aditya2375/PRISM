"""Encrypted, signed key backups with verify-before-restore.

Format (JSON): ``{"v":1,"manifest":{...},"kem_ct":..,"blob":..,"sig":..}``

* The payload (state, audit log, revoked set) is sealed with a random AES-256-GCM
  key. That key is wrapped to the operator's backup public key (hybrid ML-KEM +
  X25519); the backup secret key is held offline by the operator.
* The manifest binds the payload hash, audit length and head. The whole container
  is signed with the service's ML-DSA key.
* Restore verifies signature, decryption tag, payload hash, audit chain and state
  consistency BEFORE writing anything, and only into an empty directory. Any
  failure raises ``BackupError`` and leaves the target untouched.
* Revocations newer than the backup are never lost: pass the live ``revoked.log``
  and it is merged into the restored state (union only).
* Each backup carries a monotonic counter; restoring one older than the live
  counter is refused unless ``allow_older`` is set.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from . import crypto as c
from .audit import verify_chain
from .service import GuardService, _atomic_write


class BackupError(Exception):
    pass


def keygen(out_dir: str | Path) -> None:
    """Create the operator's backup key pair. Keep ``backup.key`` offline."""
    pub, sec = c.kem_keygen()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    _atomic_write(out / "backup.pub", pub, 0o644)
    _atomic_write(out / "backup.key", sec, 0o600)


def _ctx(manifest: dict[str, Any]) -> bytes:
    return b"kig/v1/backup|" + c.sha256_hex(c.canonical(manifest)).encode()


def _counter(d: str | Path) -> int:
    try:
        return int((Path(d) / "backup.counter").read_text().strip())
    except (OSError, ValueError):
        return 0


def create(svc: GuardService, backup_pub: bytes, out_path: str | Path) -> dict[str, Any]:
    with svc._lock:  # consistent snapshot
        counter = _counter(svc.dir) + 1
        _atomic_write(svc.dir / "backup.counter", str(counter).encode())
        payload = {
            "state": json.loads(json.dumps(svc.state)),
            "audit": list(svc.audit.entries),
            "revoked": sorted(svc.revoked),
        }
        raw = c.canonical(payload)
        manifest = {
            "counter": counter,
            "created": round(svc.clock(), 3),
            "payload_sha256": c.sha256_hex(raw),
            "audit_len": len(svc.audit.entries),
            "audit_head": svc.audit.head,
            "service_pub_sha256": c.sha256_hex(svc.pub),
        }
        kem_ct, kek = c.kem_encaps(backup_pub, _ctx(manifest))
        dek = c.random_key()
        doc = {
            "v": 1,
            "manifest": manifest,
            "kem_ct": c.b64e(kem_ct),
            "wrapped_dek": c.b64e(c.aead_encrypt(kek, dek, _ctx(manifest))),
            "blob": c.b64e(c.aead_encrypt(dek, raw, _ctx(manifest))),
        }
        doc["sig"] = c.b64e(c.sign(svc._sec, "backup", c.canonical(doc)))
    _atomic_write(Path(out_path), json.dumps(doc, sort_keys=True).encode(), 0o600)
    return manifest


def verify_and_open(path: str | Path, backup_pub: bytes, backup_sec: bytes,
                    service_pub: bytes) -> dict[str, Any]:
    """Return the verified payload or raise BackupError. Nothing is written."""
    try:
        doc = json.loads(Path(path).read_bytes())
        sig = c.b64d(doc.pop("sig"))
        manifest = doc["manifest"]
        if doc.get("v") != 1:
            raise BackupError("unsupported backup version")
    except BackupError:
        raise
    except Exception:  # noqa: BLE001
        raise BackupError("backup file is damaged or not a backup (unreadable)") from None
    if not c.verify(service_pub, "backup", c.canonical(doc), sig):
        raise BackupError("signature check failed: backup was modified or is not from this service")
    try:
        kek = c.kem_decaps(backup_sec, backup_pub, c.b64d(doc["kem_ct"]), _ctx(manifest))
        dek = c.aead_decrypt(kek, c.b64d(doc["wrapped_dek"]), _ctx(manifest))
        raw = c.aead_decrypt(dek, c.b64d(doc["blob"]), _ctx(manifest))
    except Exception:  # noqa: BLE001
        raise BackupError("decryption failed: wrong backup key or damaged data") from None
    if c.sha256_hex(raw) != manifest["payload_sha256"]:
        raise BackupError("payload hash does not match manifest")
    if c.sha256_hex(service_pub) != manifest["service_pub_sha256"]:
        raise BackupError("backup was made by a different service key")
    try:
        payload = json.loads(raw)
        entries, state = payload["audit"], payload["state"]
    except Exception:  # noqa: BLE001
        raise BackupError("payload is malformed") from None
    ok, why = verify_chain(entries, service_pub)
    if not ok:
        raise BackupError(f"audit chain in backup is invalid: {why}")
    if len(entries) != manifest["audit_len"] or (entries and entries[-1]["hash"] != manifest["audit_head"]):
        raise BackupError("audit length or head does not match manifest")
    if state.get("applied", 0) > len(entries):
        raise BackupError("state is ahead of the audit log")
    if not isinstance(manifest.get("counter"), int) or manifest["counter"] < 1:
        raise BackupError("manifest has no valid monotonic counter")
    payload["_counter"] = manifest["counter"]
    return payload


def restore(path: str | Path, dest_dir: str | Path, backup_pub: bytes, backup_sec: bytes,
            service_pub_path: str | Path, service_key_path: str | Path,
            live_revoked_log: str | Path | None = None, live_dir: str | Path | None = None,
            allow_older: bool = False) -> dict[str, Any]:
    """Verify, then write a fresh data directory. Returns a short report."""
    dest = Path(dest_dir)
    if dest.exists() and any(dest.iterdir()):
        raise BackupError("destination is not empty; refusing to overwrite")
    service_pub = Path(service_pub_path).read_bytes()
    payload = verify_and_open(path, backup_pub, backup_sec, service_pub)
    counter = payload_counter = payload.get("_counter", 0)
    if live_dir is not None and not allow_older and _counter(live_dir) > payload_counter:
        raise BackupError(f"older backup refused: counter {payload_counter} < live counter "
                          f"{_counter(live_dir)} (pass allow_older to override)")
    revoked = set(payload["revoked"])
    if live_revoked_log and Path(live_revoked_log).exists():
        for line in Path(live_revoked_log).read_text().splitlines():
            if line.strip():
                revoked.add(line.split("\t")[0])
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "audit.jsonl").write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in payload["audit"]))
    os.chmod(dest / "audit.jsonl", 0o600)
    _atomic_write(dest / "server_sign.pub", service_pub, 0o644)
    _atomic_write(dest / "server_sign.key", Path(service_key_path).read_bytes(), 0o600)
    st = dict(payload["state"])
    st["_sig"] = c.b64e(c.sign(Path(service_key_path).read_bytes(), "state", c.canonical(payload["state"])))
    _atomic_write(dest / "state.json", json.dumps(st, sort_keys=True).encode())
    _atomic_write(dest / "revoked.log", "".join(f"{d}\t0\n" for d in sorted(revoked)).encode())
    _atomic_write(dest / "backup.counter", str(max(counter, _counter(live_dir) if live_dir else 0)).encode())
    return {"audit_entries": len(payload["audit"]), "revoked": sorted(revoked), "counter": counter}
