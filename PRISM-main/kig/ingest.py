"""Feed outside log lines (JSON lines or CSV) into the Detector.

The format of the logs is not known in advance, so every name is configurable: which field holds the timestamp,
the identity, the service, the event and so on, how timestamps are written, and which event values mean what.
See docs/INGEST.md. Usage:

    python -m kig.ingest logs.jsonl                     # JSON lines with the default field names
    python -m kig.ingest access.csv --config map.json   # CSV, fields and events renamed in map.json
    python -m kig.ingest - < logs.jsonl                 # stdin

Output: one JSON alert per line on stdout, then one summary line on stderr (lines read, fed, skipped and why).
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator

from kig.detect import Alert, Detector

# Canonical kinds an outside event can be mapped to, and the audit entry type the Detector knows them by.
KINDS = {
    "access": "access.granted",               # identity used a service / resource successfully
    "auth_failure": "auth.bad_signature",     # failed login or failed authentication (the identity is a claim)
    "revoked_use": "auth.revoked_device_use", # a revoked / disabled credential was used
    "replay": "auth.replay",
    "revoked": "device.revoked",              # a credential was revoked
    "enrolled": "device.enrolled",            # a credential / device / key was issued to the identity
    "admin_created": "role.changed",          # an admin account was created (old role: none)
    "role_admin": "role.changed",             # an existing account was made admin
    "other": "ext.event",                     # kept for ordering and service tracking, no rule of its own
}

DEFAULT_CONFIG: dict[str, Any] = {
    "format": "auto",                 # "jsonl", "csv" or "auto" (by first non-blank character)
    "fields": {                       # canonical name -> field name (or list of candidate names) in the log
        "ts": ["timestamp", "ts", "time", "@timestamp", "datetime"],
        "identity": ["identity", "user", "username", "principal", "subject", "account"],
        "service": ["service", "app", "application", "host", "target"],
        "event": ["event", "action", "event_type", "type", "method"],
        "source": ["source", "ip", "src_ip", "client_ip", "remote_addr"],
        "resource": ["resource", "path", "url", "file", "object"],
        "outcome": ["outcome", "status", "result", "status_code"],
        "device": ["device", "device_id", "credential", "key_id"],
        "by": ["by", "actor", "admin"],
    },
    "ts_format": "auto",              # "auto" (epoch seconds/ms or ISO 8601), "epoch", "epoch_ms", "iso", or a strptime pattern
    "events": {                       # event value (lower-cased) -> kind; anything unlisted is "other"
        "login": "access", "access": "access", "read": "access", "get": "access", "post": "access",
        "put": "access", "delete": "access", "request": "access", "download": "access", "query": "access",
        "login_failed": "auth_failure", "failed_login": "auth_failure", "auth_failure": "auth_failure",
        "auth_failed": "auth_failure", "login_failure": "auth_failure", "bad_password": "auth_failure",
        "revoked_use": "revoked_use", "revoked_token_use": "revoked_use", "disabled_login": "revoked_use",
        "replay": "replay",
        "revoke": "revoked", "revoked": "revoked", "key_revoked": "revoked",
        "enroll": "enrolled", "enrolled": "enrolled", "device_enrolled": "enrolled", "key_issued": "enrolled",
        "create_admin": "admin_created", "admin_created": "admin_created",
        "grant_admin": "role_admin", "promote_admin": "role_admin", "role_admin": "role_admin",
    },
    # an outcome in this list turns an "access" (or "other") event into an "auth_failure": an HTTP 401/403, "denied"
    "failure_outcomes": ["fail", "failed", "failure", "denied", "deny", "unauthorized", "forbidden", "401", "403", "false"],
    "default_service": "external",
    "sort": False,                    # true: sort all lines by timestamp first (reads the whole input into memory)
}


class LineError(ValueError):
    pass


def load_config(path: str | None) -> dict[str, Any]:
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if path:
        with open(path, encoding="utf-8") as f:
            user = json.load(f)
        if not isinstance(user, dict):
            raise ValueError("config must be a JSON object")
        for k, v in user.items():
            if k not in DEFAULT_CONFIG:
                raise ValueError(f"unknown config key {k!r} (known: {', '.join(DEFAULT_CONFIG)})")
            if k in ("fields", "events") and isinstance(v, dict):
                cfg[k].update(v)       # override one mapping without restating the rest
            else:
                cfg[k] = v
    for raw, kind in cfg["events"].items():
        if kind not in KINDS:
            raise ValueError(f"event {raw!r} maps to unknown kind {kind!r} (known: {', '.join(KINDS)})")
    cfg["events"] = {str(k).lower(): v for k, v in cfg["events"].items()}
    cfg["failure_outcomes"] = {str(x).lower() for x in cfg["failure_outcomes"]}
    return cfg


def parse_ts(v: Any, fmt: str) -> float:
    if v is None or v == "":
        raise LineError("no timestamp")
    if fmt in ("auto", "epoch", "epoch_ms"):
        try:
            x = float(v)
            if fmt == "epoch_ms" or (fmt == "auto" and x > 1e11):   # auto: past year 5138 in seconds means milliseconds
                x /= 1000.0
            return x
        except (TypeError, ValueError):
            if fmt != "auto":
                raise LineError(f"timestamp {v!r} is not a number") from None
    s = str(v).strip()
    try:
        if fmt in ("auto", "iso"):
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        else:
            dt = datetime.strptime(s, fmt)
    except ValueError:
        raise LineError(f"cannot read timestamp {s!r} with format {fmt!r}") from None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)   # a timestamp with no zone is taken as UTC (stated in docs/INGEST.md)
    return dt.timestamp()


def _get(rec: dict[str, Any], names: Any) -> Any:
    for n in [names] if isinstance(names, str) else list(names or []):
        if n in rec and rec[n] not in (None, ""):
            return rec[n]
    return None


def records(lines: Iterable[str], fmt: str) -> Iterator[tuple[int, dict[str, Any] | None, str]]:
    """Yield (line number, record or None, error)."""
    it = iter(lines)
    if fmt == "auto":
        buf = []
        for ln in it:
            buf.append(ln)
            if ln.strip():
                break
        first = next((b for b in buf if b.strip()), "")
        fmt = "jsonl" if first.lstrip().startswith("{") else "csv"
        it = _chain(buf, it)
    if fmt == "jsonl":
        for no, ln in enumerate(it, 1):
            if not ln.strip():
                continue
            try:
                r = json.loads(ln)
            except ValueError:
                yield no, None, "not JSON"
                continue
            yield (no, r, "") if isinstance(r, dict) else (no, None, "not a JSON object")
    elif fmt == "csv":
        rd = csv.DictReader(it)
        for r in rd:
            yield rd.line_num, {k.strip(): (v.strip() if isinstance(v, str) else v) for k, v in r.items() if k}, ""
    else:
        raise ValueError(f"unknown format {fmt!r}")


def _chain(a, b):
    yield from a
    yield from b


def to_entry(rec: dict[str, Any], seq: int, cfg: dict[str, Any]) -> dict[str, Any]:
    """One outside record as an audit-shaped entry the Detector understands."""
    f = cfg["fields"]
    ts = parse_ts(_get(rec, f["ts"]), cfg["ts_format"])
    ident = _get(rec, f["identity"])
    if ident is None:
        raise LineError("no identity")
    ident = str(ident)[:128]
    svc = str(_get(rec, f["service"]) or cfg["default_service"])[:128]
    raw_ev = str(_get(rec, f["event"]) or "")
    kind = cfg["events"].get(raw_ev.lower(), "other")
    outcome = _get(rec, f["outcome"])
    if outcome is not None and str(outcome).lower() in cfg["failure_outcomes"] and kind in ("access", "other"):
        kind = "auth_failure"
    src = str(_get(rec, f["source"]) or "unknown")[:64]
    res = _get(rec, f["resource"])
    dev = str(_get(rec, f["device"]) or ident)[:128]
    by = str(_get(rec, f["by"]) or "unknown")[:128]
    d: dict[str, Any] = {"service": svc, "source": src, "raw_event": raw_ev[:64]}
    if kind == "access":
        d.update(device=dev, user=ident, file=f"{svc}:{res}" if res is not None else svc)
    elif kind in ("auth_failure", "replay"):
        d.update(device=ident, cmd=raw_ev[:32])
    elif kind == "revoked_use":
        d.update(device=dev, user=ident, cmd=raw_ev[:32], status="revoked")
    elif kind == "revoked":
        d.update(device=dev, user=ident, by=by)
    elif kind == "enrolled":
        d.update(device=dev, user=ident, by=by)
    elif kind in ("admin_created", "role_admin"):
        d.update(user=ident, old=None if kind == "admin_created" else "member", new="admin", by=by)
    else:
        d.update(user=ident, device=dev)
    return {"type": KINDS[kind], "seq": seq, "ts": ts, "actor": by if kind in ("admin_created", "role_admin", "revoked", "enrolled") else dev,
            "data": d, "line_kind": kind}


def run(lines: Iterable[str], cfg: dict[str, Any], detector: Detector | None = None,
        seq0: int = 0) -> tuple[list[Alert], dict[str, Any]]:
    """Feed every line to the detector. ``seq0``: sequence numbers continue from here (several files, one detector)."""
    det = detector or Detector(service="ingest")
    stats: dict[str, Any] = {"lines": 0, "fed": 0, "skipped": 0, "reasons": {}, "kinds": {}}
    entries = []
    for no, rec, err in records(lines, cfg["format"]):
        stats["lines"] += 1
        try:
            if rec is None:
                raise LineError(err)
            entries.append(to_entry(rec, seq0 + stats["lines"], cfg))
        except LineError as e:
            stats["skipped"] += 1
            stats["reasons"][str(e)] = stats["reasons"].get(str(e), 0) + 1
    if cfg.get("sort"):
        entries.sort(key=lambda e: (e["ts"], e["seq"]))
    alerts: list[Alert] = []
    for e in entries:
        kind = e.pop("line_kind")
        stats["kinds"][kind] = stats["kinds"].get(kind, 0) + 1
        if kind == "admin_created":
            det.observe({"type": "user.created", "seq": e["seq"], "ts": e["ts"], "actor": e["actor"],
                         "data": {"user": e["data"]["user"], "role": "admin", "by": e["data"]["by"], "service": e["data"]["service"]}})
        alerts.extend(det.observe(e))
        stats["fed"] += 1
    return alerts, stats


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m kig.ingest", description=__doc__.split("\n\n")[0])
    ap.add_argument("logs", nargs="+", help="log files (JSON lines or CSV); - for stdin")
    ap.add_argument("--config", help="JSON file that renames fields, events and the timestamp format (docs/INGEST.md)")
    ap.add_argument("--format", choices=["auto", "jsonl", "csv"], help="overrides the config")
    ap.add_argument("--sort", action="store_true", help="sort by timestamp before detection")
    a = ap.parse_args(argv)
    try:
        cfg = load_config(a.config)
    except (OSError, ValueError) as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2
    if a.format:
        cfg["format"] = a.format
    if a.sort:
        cfg["sort"] = True
    det, total = Detector(service="ingest"), {"lines": 0, "fed": 0, "skipped": 0, "reasons": {}, "kinds": {}, "alerts": 0}
    for path in a.logs:
        fh = io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8", errors="replace") if path == "-" \
            else open(path, encoding="utf-8", errors="replace", newline="")
        with fh:
            alerts, st = run(fh, cfg, det, seq0=total["lines"])
        for al in alerts:
            print(json.dumps(al.as_data(), sort_keys=True))
        total["alerts"] += len(alerts)
        for k in ("lines", "fed", "skipped"):
            total[k] += st[k]
        for k in ("reasons", "kinds"):
            for r, n in st[k].items():
                total[k][r] = total[k].get(r, 0) + n
    print(json.dumps({"summary": total}, sort_keys=True), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
