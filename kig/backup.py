"""Encrypted, signed key backups with verify-before-restore.

Format: a tar archive (manifest.json, meta.sealed.json, blobs/<sha256>), see ``create``.

* The payload (state, audit log, revoked set) is sealed with a random AES-256-GCM
  key. That key is wrapped to the operator's backup public key (hybrid ML-KEM +
  X25519); the backup secret key is held offline by the operator.
* The manifest binds the payload hash, audit length and head. The whole container
  is signed with the service's ML-DSA key.
* Restore verifies signature, decryption tag, payload hash, audit chain and state
  consistency BEFORE writing anything, and only into an empty directory. Any
  failure raises ``BackupError`` and leaves the target untouched.
* Revocations newer than the backup are only kept if the operator supplies the live
  ``revoked.log`` (merged union-only) or explicitly accepts the rollback; see ``restore``.
* Each backup carries a monotonic counter; restoring one older than the live
  known counter (``min_counter`` or ``live_dir``) is refused unless the operator overrides.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import tarfile
import time
from pathlib import Path
from typing import Any

from . import crypto as c
from . import vault
from .audit import verify_chain
from .service import GuardService, _atomic_write
from .store import encode_snapshot, peek_meta


class BackupError(Exception):
    pass


def load_secret(path: str | Path, passphrase: str | None = None) -> bytes:
    raw = Path(path).read_bytes()
    return vault.open_(raw, passphrase or vault.passphrase_from_env(), "prism/backup-key") if vault.is_sealed(raw) else raw


def keygen(out_dir: str | Path, passphrase: str | None = None) -> None:
    """Create the operator's backup key pair. Keep ``backup.key`` offline.

    With a passphrase (or PRISM_PASSPHRASE) the secret key is encrypted at rest."""
    pub, sec = c.kem_keygen()
    passphrase = passphrase or vault.passphrase_from_env()
    if passphrase:
        sec = vault.seal(sec, passphrase, "prism/backup-key")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    _atomic_write(out / "backup.pub", pub, 0o644)
    _atomic_write(out / "backup.key", sec, 0o600)


def _ctx(manifest: dict[str, Any]) -> bytes:
    return b"kig/v1/backup|" + c.sha256_hex(c.canonical(manifest)).encode()


def _generation(d: str | Path) -> int:
    try:
        return int(peek_meta(d).get("restore_generation", 0))
    except (ValueError, TypeError):
        return 0


def _counter(d: str | Path) -> int:
    """Highest counter a data directory remembers: its signed-state value or the plain file."""
    best = 0
    try:
        best = int((Path(d) / "backup.counter").read_text().strip())
    except (OSError, ValueError):
        pass
    try:
        best = max(best, int(peek_meta(d).get("backup_counter", 0)))
    except (ValueError, TypeError):
        pass
    return best


_BLOB_RE = re.compile(r"^blobs/[0-9a-f]{64}$")
_CHUNK = 1 << 20


def _ctx_fields(m: dict[str, Any]) -> bytes:
    keep = {k: m[k] for k in ("counter", "created", "audit_len", "audit_head", "service_pub_sha256", "blobs_sha256")}
    return b"kig/v1/backup|" + c.sha256_hex(c.canonical(keep)).encode()


def _blobs_sha256(hashes: list[str]) -> str:
    return c.sha256_hex(c.canonical(sorted(hashes)))


def create(svc: GuardService, backup_pub: bytes, out_path: str | Path) -> dict[str, Any]:
    """Write a backup as a tar archive: ``manifest.json``, ``meta.sealed.json`` and ``blobs/<sha256>``.

    The metadata (state, audit log, revoked set) is sealed to the backup public key with the
    ordinary HPKE and AES-GCM helpers. Blobs are already ciphertext made on the clients and are
    named by their hash, so they are copied from disk as they are, one file at a time: memory use
    follows the size of the metadata, not of the stored data. The manifest lists every blob hash and
    is signed with the service key. Writes are paused while the archive is built.
    """
    with svc._lock:
        # the counter lives in the signed state; the plain file is only a convenience copy
        counter = max(int(svc.state.get("backup_counter", 0)), _counter(svc.dir)) + 1
        svc.state["backup_counter"] = counter
        svc._persist()
        _atomic_write(svc.dir / "backup.counter", str(counter).encode())
        hashes = sorted(svc.blob_hashes())
        for h in hashes:
            if not svc._blob_path(h).exists():
                raise BackupError(f"stored blob {h[:12]} is missing; refusing to make a backup that cannot restore")
        meta = c.canonical({
            "state": json.loads(json.dumps(svc.state)),
            "audit": list(svc.audit.entries),
            "revoked": sorted(svc.revoked),
        })
        manifest = {
            "counter": counter,
            "created": round(svc.clock(), 3),
            "audit_len": len(svc.audit.entries),
            "audit_head": svc.audit.head,
            "service_pub_sha256": c.sha256_hex(svc.pub),
            "blobs_sha256": _blobs_sha256(hashes),
            "blobs": hashes,
        }
        ctx = _ctx_fields(manifest)
        kem_ct, kek = c.kem_encaps(backup_pub, ctx)
        dek = c.random_key()
        sealed = json.dumps({
            "kem_ct": c.b64e(kem_ct),
            "wrapped_dek": c.b64e(c.aead_encrypt(kek, dek, ctx)),
            "blob": c.b64e(c.aead_encrypt(dek, meta, ctx)),
        }, sort_keys=True).encode()
        manifest["meta_sha256"] = c.sha256_hex(sealed)
        doc = {"v": 2, "suite": c.SUITE, "manifest": manifest}
        doc["sig"] = c.b64e(c.sign(svc._sec, "backup", c.canonical(doc)))
        out = Path(out_path)
        tmp = out.with_name(out.name + ".tmp")
        try:
            with tarfile.open(tmp, "w", format=tarfile.PAX_FORMAT) as tf:
                _add_bytes(tf, "manifest.json", json.dumps(doc, sort_keys=True).encode())
                _add_bytes(tf, "meta.sealed.json", sealed)
                for h in hashes:
                    tf.add(svc._blob_path(h), arcname=f"blobs/{h}", recursive=False,
                           filter=_plain_member)
            fd = os.open(tmp, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            os.chmod(tmp, 0o600)
            os.replace(tmp, out)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
    return {k: v for k, v in manifest.items() if k != "blobs"} | {"blob_count": len(hashes)}


def _plain_member(ti: tarfile.TarInfo) -> tarfile.TarInfo:
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ""
    ti.mode = 0o600
    ti.mtime = 0
    return ti


def _add_bytes(tf: tarfile.TarFile, name: str, data: bytes) -> None:
    ti = _plain_member(tarfile.TarInfo(name))
    ti.size = len(data)
    tf.addfile(ti, io.BytesIO(data))


def _open_tar(path: str | Path) -> tarfile.TarFile:
    try:
        return tarfile.open(path, "r:")
    except Exception:  # noqa: BLE001
        raise BackupError("backup file is damaged or not a backup (unreadable)") from None


def _members(tf: tarfile.TarFile) -> dict[str, tarfile.TarInfo]:
    """Index regular files by name; refuse anything that is not one of the three expected kinds."""
    out: dict[str, tarfile.TarInfo] = {}
    try:
        for ti in tf:
            ok = ti.name in ("manifest.json", "meta.sealed.json") or _BLOB_RE.match(ti.name)
            if not ok or not ti.isreg() or ti.name in out:
                raise BackupError(f"unexpected or duplicate entry in backup: {ti.name[:40]!r}")
            out[ti.name] = ti
    except BackupError:
        raise
    except Exception:  # noqa: BLE001
        raise BackupError("backup file is damaged or not a backup (unreadable)") from None
    return out


def _read_small(tf: tarfile.TarFile, ti: tarfile.TarInfo, limit: int = 1 << 31) -> bytes:
    if ti.size > limit:
        raise BackupError("backup member is too large")
    fh = tf.extractfile(ti)
    return fh.read() if fh else b""


def _hash_stream(tf: tarfile.TarFile, ti: tarfile.TarInfo, sink=None) -> str:
    h = hashlib.sha256()
    fh = tf.extractfile(ti)
    if fh is None:
        raise BackupError("backup member cannot be read")
    while True:
        chunk = fh.read(_CHUNK)
        if not chunk:
            break
        h.update(chunk)
        if sink is not None:
            sink.write(chunk)
    return h.hexdigest()


def verify_and_open(path: str | Path, backup_pub: bytes, backup_sec: bytes,
                    service_pub: bytes) -> dict[str, Any]:
    """Return the verified metadata payload or raise BackupError. Nothing is written.

    Every blob is read once and hashed (streaming) and compared with the signed manifest.
    """
    tf = _open_tar(path)
    try:
        mem = _members(tf)
        try:
            doc = json.loads(_read_small(tf, mem["manifest.json"], 1 << 28))
            sig = c.b64d(doc.pop("sig"))
            manifest = doc["manifest"]
            if doc.get("v") != 2:
                raise BackupError("unsupported backup version")
            c.require_suite(doc, "backup")
        except BackupError:
            raise
        except c.CryptoError as e:
            raise BackupError(str(e)) from None
        except Exception:  # noqa: BLE001
            raise BackupError("backup file is damaged or not a backup (unreadable)") from None
        if not c.verify(service_pub, "backup", c.canonical(doc), sig):
            raise BackupError("signature check failed: backup was modified or is not from this service")
        try:
            hashes = manifest["blobs"]
            if (not isinstance(hashes, list) or hashes != sorted(set(hashes))
                    or any(not isinstance(h, str) or not re.fullmatch(r"[0-9a-f]{64}", h) for h in hashes)):
                raise ValueError
            if manifest["blobs_sha256"] != _blobs_sha256(hashes):
                raise ValueError
            if not isinstance(manifest.get("counter"), int) or manifest["counter"] < 1:
                raise BackupError("manifest has no valid monotonic counter")
            sealed_ti = mem["meta.sealed.json"]
            sealed = _read_small(tf, sealed_ti, 1 << 31)
        except BackupError:
            raise
        except Exception:  # noqa: BLE001
            raise BackupError("manifest is malformed or the backup is incomplete") from None
        if c.sha256_hex(sealed) != manifest.get("meta_sha256"):
            raise BackupError("sealed metadata does not match the manifest")
        if c.sha256_hex(service_pub) != manifest["service_pub_sha256"]:
            raise BackupError("backup was made by a different service key")
        try:
            sd = json.loads(sealed)
            ctx = _ctx_fields(manifest)
            kek = c.kem_decaps(backup_sec, backup_pub, c.b64d(sd["kem_ct"]), ctx)
            dek = c.aead_decrypt(kek, c.b64d(sd["wrapped_dek"]), ctx)
            raw = c.aead_decrypt(dek, c.b64d(sd["blob"]), ctx)
        except Exception:  # noqa: BLE001
            raise BackupError("decryption failed: wrong backup key or damaged data") from None
        try:
            payload = json.loads(raw)
            entries, state = payload["audit"], payload["state"]
        except Exception:  # noqa: BLE001
            raise BackupError("payload is malformed") from None
        ok, why = verify_chain(entries, service_pub)
        if not ok:
            raise BackupError(f"audit chain in backup is invalid: {why}")
        names = {f"blobs/{h}" for h in hashes}
        if {n for n in mem if n.startswith("blobs/")} != names:
            raise BackupError("blobs in the archive do not match the signed manifest")
        for h in hashes:
            if _hash_stream(tf, mem[f"blobs/{h}"]) != h:
                raise BackupError(f"blob {h[:12]} does not match its hash")
        try:
            need = {f["ct"] for f in state["files"].values()} | {f["prev"]["ct"] for f in state["files"].values() if f.get("prev")}
        except Exception:  # noqa: BLE001
            raise BackupError("payload is malformed") from None
        if need - set(hashes):
            raise BackupError("backup is missing ciphertext blobs referenced by state")
        if len(entries) != manifest["audit_len"] or (entries and entries[-1]["hash"] != manifest["audit_head"]):
            raise BackupError("audit length or head does not match manifest")
        n = state.get("applied", 0)
        if not isinstance(n, int) or n < 0 or n > len(entries):
            raise BackupError("state is ahead of the audit log")
        if n and entries[n - 1]["hash"] != state.get("audit_head"):
            raise BackupError("state does not match the audit log head it claims")
        payload["_counter"] = manifest["counter"]
        payload["_created"] = manifest.get("created", 0.0)
        payload["_blobs"] = hashes
        return payload
    finally:
        tf.close()


def _read_service_key(path: str | Path, service_pub: bytes) -> tuple[bytes, bytes]:
    """Return (raw file bytes, usable secret). Opens a passphrase-sealed key and checks it matches the public key."""
    raw = Path(path).read_bytes()
    try:
        sec = vault.open_(raw, vault.passphrase_from_env(), "prism/server-key") if vault.is_sealed(raw) else raw
        probe = b"prism/restore-key-check"
        ok = c.verify(service_pub, "restore-check", probe, c.sign(sec, "restore-check", probe))
    except vault.VaultError as e:
        raise BackupError(f"service key cannot be opened: {e}") from None
    except Exception:  # noqa: BLE001
        raise BackupError("service key file is not a valid key") from None
    if not ok:
        raise BackupError("service key does not match the service public key")
    return raw, sec


def _parse_revoked(text: str) -> set[str]:
    good = text.rfind("\n") + 1                 # ignore a torn, unterminated last line
    return {l.split("\t")[0].strip() for l in text[:good].split("\n") if l.strip()}


def restore(path: str | Path, dest_dir: str | Path, backup_pub: bytes, backup_sec: bytes,
            service_pub_path: str | Path, service_key_path: str | Path,
            live_revoked_log: str | Path | None = None, live_dir: str | Path | None = None,
            allow_older: bool = False, min_counter: int | None = None,
            accept_rollback: bool = False, accept_counter_rollback: bool = False,
            accept_lost_revocations: bool = False) -> dict[str, Any]:
    """Verify everything, build the new directory aside, then move it into place.

    Two guards stop a stale backup from undoing later security decisions, and each needs
    either evidence or an explicit decision from the operator:

    ``accept_rollback`` is shorthand for ``accept_counter_rollback`` plus ``accept_lost_revocations``.
    Whatever is accepted is recorded as ``restore.rollback_accepted`` in the restored audit chain.

    * counter: pass ``min_counter`` (the highest backup counter you know of, written down when
      backups are made) or ``live_dir`` (a surviving data directory), else ``allow_older`` or
      ``accept_rollback``. A backup below the known counter is refused.
    * revocations: pass ``live_revoked_log`` (a surviving revoked.log, merged union-only) or
      ``accept_rollback``. Without either, devices revoked after the backup would come back.

    Nothing is written to ``dest_dir`` until every check has passed; a failure leaves no residue.
    """
    import shutil

    dest = Path(dest_dir)
    if dest.exists() and any(dest.iterdir()):
        raise BackupError("destination is not empty; refusing to overwrite")
    service_pub = Path(service_pub_path).read_bytes()
    key_raw, key_sec = _read_service_key(service_key_path, service_pub)
    payload = verify_and_open(path, backup_pub, backup_sec, service_pub)
    accept_counter_rollback = accept_counter_rollback or accept_rollback
    accept_lost_revocations = accept_lost_revocations or accept_rollback
    counter = payload["_counter"]
    accepted: list[str] = []
    known = max([x for x in (min_counter, _counter(live_dir) if live_dir else None) if x is not None], default=None)
    if known is None and not (allow_older or accept_counter_rollback):
        raise BackupError("cannot judge how old this backup is: pass min_counter (highest known backup counter), "
                          "live_dir, or accept_rollback")
    if known is None or counter < known:
        accepted.append("counter")
    if known is not None and counter < known and not (allow_older or accept_counter_rollback):
        raise BackupError(f"older backup refused: counter {counter} < known counter {known} "
                          "(pass allow_older to override)")
    revoked = set(payload["revoked"])
    if live_revoked_log is not None and Path(live_revoked_log).exists():
        revoked |= _parse_revoked(Path(live_revoked_log).read_text())
    elif not accept_lost_revocations:
        raise BackupError("no live revoked list supplied: devices revoked after this backup would be re-activated. "
                          "Pass live_revoked_log, or accept_lost_revocations if none survives")
    else:
        accepted.append("revocations")
    part = dest.with_name(dest.name + ".partial")
    if part.exists():
        shutil.rmtree(part)
    try:
        part.mkdir(parents=True, mode=0o700)
        entries = payload["audit"]
        _atomic_write(part / "audit.jsonl", "".join(json.dumps(e, sort_keys=True) + "\n" for e in entries).encode())
        st = dict(payload["state"])
        if entries:
            last = entries[-1]
            _atomic_write(part / "audit.head", json.dumps({"seq": last["seq"], "hash": last["hash"], "sig": last["sig"]}).encode())
        # every restore is recorded and bumps the restore generation replicas compare snapshots by
        # wall-clock milliseconds keep it increasing even for a repeated restore without live_dir
        gen = max(int(st.get("restore_generation", 0)), _generation(live_dir) if live_dir else 0,
                  int(time.time() * 1000)) + 1
        st["restore_generation"] = gen
        from .audit import AuditLog
        alog = AuditLog(part / "audit.jsonl", key_sec, service_pub)
        alog.append(time.time(), "restore.completed", "operator",
                    {"unchecked": accepted, "backup_counter": counter, "known_counter": known, "generation": gen})
        entries = alog.entries
        st["applied"], st["audit_head"] = len(entries), alog.head
        _atomic_write(part / "server_sign.pub", service_pub, 0o644)
        _atomic_write(part / "server_sign.key", key_raw, 0o600)
        tf = _open_tar(path)
        try:
            mem = _members(tf)
            for h in payload["_blobs"]:
                bp = part / "blobs" / h[:2] / h
                bp.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with open(bp, "wb") as sink:
                    if _hash_stream(tf, mem[f"blobs/{h}"], sink) != h:
                        raise BackupError(f"blob {h[:12]} changed while restoring")
                    sink.flush()
                    os.fsync(sink.fileno())
        finally:
            tf.close()
        _atomic_write(part / "state.json", encode_snapshot(st, key_sec, os.urandom(8).hex()))
        stamp = payload.get("_created", 0.0)
        _atomic_write(part / "revoked.log", "".join(f"{d}\t{stamp:.3f}\n" for d in sorted(revoked)).encode())
        _atomic_write(part / "backup.counter", str(max(counter, known or 0)).encode())
        if dest.exists():
            dest.rmdir()
        os.rename(part, dest)
        dfd = os.open(dest.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except BaseException:
        shutil.rmtree(part, ignore_errors=True)
        raise
    return {"audit_entries": len(entries), "revoked": sorted(revoked), "counter": counter}
