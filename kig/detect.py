"""Explainable detection rules.

Every rule is a plain function of recent audit events. An alert names the rule,
says in words why it fired, and lists the audit sequence numbers that caused it,
so an operator (or judge) can replay the evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

BURST_WINDOW_S = 60
BURST_THRESHOLD = 3
FRESH_ACCOUNT_S = 600
LOCKOUT_S = 300
# Access-pattern rules. Reads are the audit entries "access.granted" (device, user, file). All numbers are tunable
# defaults chosen for a small team, not measured on real traffic.
BULK_WINDOW_S = 60
BULK_READ_FILES = 15          # distinct files read by one device inside BULK_WINDOW_S
LATERAL_WINDOW_S = 300
LATERAL_NEW_FILES = 4         # files a device had never read before, inside LATERAL_WINDOW_S ...
LATERAL_BASELINE = 2          # ... after it had already read at least this many files (so a new user is not flagged)
SLOW_WINDOW_S = 3600
SLOW_FAILURES = 8             # failed authentications from one source inside SLOW_WINDOW_S (spread thin, they stay under the burst rule)
SKEW_WARN_COUNT = 3           # stale-timestamp rejections from one device inside BURST_WINDOW_S
CLOCK_TOLERANCE_S = 30        # kig.service.SKEW_S: a signed request is accepted only within this many seconds of the node clock


@dataclass
class Alert:
    rule: str
    severity: str  # critical, high, medium, low
    explanation: str
    evidence: list[int]
    response: str = "none"
    subject: str = ""
    lock_key: str = ""
    lock_until: float = 0.0
    # who and where: structured, so a tool can act on an alert without parsing the words.
    # "unknown" is stated when the audit entry does not carry the value (never guessed).
    device: str = "unknown"
    user: str = "unknown"
    service: str = "unknown"   # the node that raised it
    event: str = "unknown"     # the audit entry type that triggered it
    source: str = "unknown"    # network source of the request, when one was logged
    actor: str = "unknown"     # the device that performed the action, when the event is an action
    services: list[str] = field(default_factory=list)   # nodes involved (filled in by the detector)
    files: list[str] = field(default_factory=list)      # files involved, for access-pattern rules

    def as_data(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "explanation": self.explanation,
            "evidence": self.evidence,
            "response": self.response,
            "subject": self.subject,
            "device": self.device,
            "user": self.user,
            "service": self.service,
            "event": self.event,
            "source": self.source,
            "actor": self.actor,
            "services": list(self.services),
            "files": list(self.files),
        }


@dataclass
class Detector:
    """Keeps a small amount of derived state; fed one audit entry at a time."""

    removed_at: dict[str, int] = field(default_factory=dict)  # device -> seq of revoke/lost
    failures: dict[tuple[str, str], list[tuple[float, int]]] = field(default_factory=dict)
    first_device_ts: dict[str, float] = field(default_factory=dict)
    max_tracked: int = 4096
    last_alert: dict[str, float] = field(default_factory=dict)
    dedupe_s: int = 60
    service: str = "unknown"
    owner_of: dict[str, str] = field(default_factory=dict)  # device -> user, from device.enrolled entries
    admins: set[str] = field(default_factory=set)
    seen_files: dict[str, dict[str, float]] = field(default_factory=dict)   # device -> file -> first read time
    reads: dict[str, list[tuple[float, int, str]]] = field(default_factory=dict)   # device -> (ts, seq, file)
    src_failures: dict[str, list[tuple[float, int]]] = field(default_factory=dict)  # source -> (ts, seq)
    stale: dict[str, list[tuple[float, int, float]]] = field(default_factory=dict)  # device -> (ts, seq, skew)

    def observe(self, entry: dict[str, Any]) -> list[Alert]:
        t, seq, ts, d = entry["type"], entry["seq"], entry["ts"], entry["data"]
        alerts: list[Alert] = []
        actor = entry.get("actor", "?")
        src = d.get("source") if isinstance(d.get("source"), str) and d.get("source") else "unknown"
        alerts = self._observe(entry, t, seq, ts, d, actor, src)
        for a in alerts:
            a.service, a.event = self.service, t
            a.services = [self.service]
            if a.source == "unknown":
                a.source = src
            if a.actor == "unknown" and actor != "?":
                a.actor = str(actor)
            if a.user == "unknown" and a.device != "unknown" and not a.rule.startswith("R3-"):
                a.user = self.owner_of.get(a.device, "unknown")
        return alerts

    def _observe(self, entry: dict[str, Any], t: str, seq: int, ts: float, d: dict[str, Any], actor: str, src: str) -> list[Alert]:
        alerts: list[Alert] = []

        if t == "service.bootstrapped" and d.get("user"):
            self.admins.add(str(d["user"]))
        if t == "role.changed" and d.get("user"):
            (self.admins.add if d.get("new") == "admin" else self.admins.discard)(str(d["user"]))
        if t in ("auth.bad_signature", "auth.unknown_device"):
            alerts.extend(self._slow_guess(seq, ts, d, src))
        if t in ("device.revoked", "device.lost"):
            self.removed_at[d["device"]] = seq
        if t in ("device.revoked", "device.lost") and d.get("admin_limited_removed"):
            alerts.append(
                Alert(
                    "R5-ADMIN-LIMITED-DEVICE-REMOVED",
                    "high",
                    f"A limited device ({d.get('device')}) of admin {d.get('user')} was removed by {actor}. "
                    "Expected when you reported a lost phone. If it was not you, the acting device may be stolen: the host "
                    "operator can remove it with `kig revoke-device` and recover with `kig recover-admin`.",
                    [seq],
                    response="recorded; a stolen full admin device can remove the owner's limited devices",
                    subject=str(d.get("user")),
                    device=str(d.get("device") or "unknown"),
                    user=str(d.get("user") or "unknown"),
                )
            )
        if t == "device.enrolled":
            self.first_device_ts.setdefault(d["user"], ts)
            if d.get("device"):
                self.owner_of[str(d["device"])] = str(d["user"])
                if len(self.owner_of) > self.max_tracked:
                    self.owner_of.pop(next(iter(self.owner_of)))
        elif t == "auth.revoked_device_use":
            dev = d["device"]
            if self._dup(f"R1:{dev}", ts):
                return alerts
            ref = self.removed_at.get(dev)
            ev = [seq] + ([ref] if ref is not None else [])
            alerts.append(
                Alert(
                    "R1-REVOKED-DEVICE-USE",
                    "critical",
                    f"Device {dev} sent a validly signed '{d.get('cmd')}' request after it was "
                    f"{d.get('status')}. The request was denied and no key material was released.",
                    ev,
                    response="denied; device stays blocked",
                    subject=dev,
                    device=str(dev),
                )
            )
        elif t == "auth.replay":
            if self._dup(f"R2:{d['device']}@{d.get('source')}", ts):
                return alerts
            alerts.append(
                Alert(
                    "R2-REPLAY",
                    "high",
                    f"A signed request from {d['device']} reused a nonce already seen. "
                    "The replay was denied.",
                    [seq],
                    response="request denied; the sender is not locked out",
                    subject=d["device"],
                    device=str(d["device"]),
                )
            )
        elif t == "auth.failures_suppressed":
            alerts.append(
                Alert(
                    "R3-AUTH-FAILURE-BURST",
                    "high",
                    f"{d['count']} further failed or limited requests in minute {d['minute']} were counted but "
                    "not logged one by one. Look at the earlier auth.* entries for the sources involved.",
                    [seq],
                    response="requests denied and rate limited; nobody is locked out",
                    subject="unauthenticated",
                    source="unknown",
                )
            )
        elif t in ("auth.bad_signature", "auth.unknown_device"):
            claimed, source = str(d.get("device", "?")), str(d.get("source"))
            key = (claimed, source)                      # a tuple: an id that contains "@" cannot be confused with a source
            hist = [x for x in self.failures.get(key, []) if ts - x[0] <= BURST_WINDOW_S]
            hist.append((ts, seq))
            self.failures[key] = hist
            if len(self.failures) > self.max_tracked:
                self.failures.pop(next(iter(self.failures)))
            if len(hist) >= BURST_THRESHOLD:
                # The device id in an unauthenticated request is only a claim. It is named in the structured fields
                # only when it is an enrolled device and the failure was a bad signature on it, and then the wording
                # says the sender may not be that device. Otherwise device and user stay "unknown".
                known = t == "auth.bad_signature" and claimed in self.owner_of
                who = (f"claiming the enrolled device '{claimed}' (the signature did not verify, so the sender may not be that device)"
                       if known else f"claiming the device id '{claimed}'")
                alerts.append(
                    Alert(
                        "R3-AUTH-FAILURE-BURST",
                        "high",
                        f"{len(hist)} failed authentications {who} within "
                        f"{BURST_WINDOW_S}s from source {source}. Requests were denied; nobody is locked out.",
                        [sq for _, sq in hist],
                        response="denied and rate limited",
                        subject=claimed if known else "unauthenticated",
                        device=claimed if known else "unknown",
                        user=self.owner_of[claimed] if known else "unknown",
                        source=source,
                    )
                )
                self.failures[key] = []
        elif t in ("access.granted", "access.granted_grace"):
            alerts.extend(self._access_rules(seq, ts, d, actor))
        elif t == "auth.stale":
            alerts.extend(self._skew_rule(seq, ts, d, src))
        elif t == "role.changed" and d.get("new") == "admin" and d.get("old") != "admin":
            born = self.first_device_ts.get(d["user"])
            fresh = born is not None and ts - born < FRESH_ACCOUNT_S
            alerts.append(
                Alert(
                    "R4-PRIVILEGE-ESCALATION",
                    "critical" if fresh else "high",
                    f"User {d['user']} was promoted from {d.get('old')} to admin by {d['by']}"
                    + (" shortly after their first device was enrolled." if fresh else "."),
                    [seq],
                    response="recorded; demote with set_role to undo",
                    subject=d["user"],
                    user=str(d["user"]),
                )
            )
        return alerts

    def _access_rules(self, seq: int, ts: float, d: dict[str, Any], actor: str) -> list[Alert]:
        dev, fid = str(d.get("device") or actor), d.get("file")
        if not isinstance(fid, str) or not dev:
            return []
        user = str(d.get("user") or self.owner_of.get(dev, "unknown"))
        known = self.seen_files.setdefault(dev, {})
        baseline = sum(1 for t0 in known.values() if ts - t0 > LATERAL_WINDOW_S)   # files it knew before the window
        is_new = fid not in known
        if is_new:
            known[fid] = ts
        if len(self.seen_files) > self.max_tracked:
            self.seen_files.pop(next(iter(self.seen_files)))
        if len(known) > self.max_tracked:
            known.pop(next(iter(known)))
        hist = [x for x in self.reads.get(dev, []) if ts - x[0] <= max(BULK_WINDOW_S, LATERAL_WINDOW_S)]
        hist.append((ts, seq, fid))
        self.reads[dev] = hist
        if len(self.reads) > self.max_tracked:
            self.reads.pop(next(iter(self.reads)))
        out: list[Alert] = []
        bulk = [x for x in hist if ts - x[0] <= BULK_WINDOW_S]
        bulk_files = sorted({x[2] for x in bulk})
        is_admin = user in self.admins
        if len(bulk_files) >= BULK_READ_FILES and not self._dup(f"R7:{dev}", ts):
            out.append(Alert(
                "R7-BULK-READ", "critical" if is_admin else "high",
                f"Device {dev} of {'admin ' if is_admin else ''}user {user} read {len(bulk_files)} different files within "
                f"{BULK_WINDOW_S}s. Each read was allowed; the volume is what is unusual. If this was not a planned export, "
                "treat the device as compromised and remove it.",
                [x[1] for x in bulk], response="recorded; reads were allowed (access was valid)", subject=dev,
                device=dev, user=user, files=bulk_files[:50]))
        if is_new and baseline >= LATERAL_BASELINE:
            fresh = [x for x in hist if ts - x[0] <= LATERAL_WINDOW_S and known.get(x[2]) == x[0]]
            names = sorted({x[2] for x in fresh})
            if len(names) >= LATERAL_NEW_FILES and not self._dup(f"R6:{dev}", ts):
                out.append(Alert(
                    "R6-LATERAL-MOVEMENT", "high",
                    f"Device {dev} of user {user}, which already had a read history, read "
                    f"{len(names)} files it had never read before within {LATERAL_WINDOW_S}s ({', '.join(names[:5])}"
                    f"{', ...' if len(names) > 5 else ''}). A valid identity moving to new data is how an intruder spreads. "
                    "This is a pattern, not proof.",
                    [x[1] for x in fresh], response="recorded; reads were allowed (access was valid)", subject=dev,
                    device=dev, user=user, files=names[:50]))
        return out

    def _slow_guess(self, seq: int, ts: float, d: dict[str, Any], src: str) -> list[Alert]:
        if src == "unknown":
            return []
        hist = [x for x in self.src_failures.get(src, []) if ts - x[0] <= SLOW_WINDOW_S]
        hist.append((ts, seq))
        self.src_failures[src] = hist
        if len(self.src_failures) > self.max_tracked:
            self.src_failures.pop(next(iter(self.src_failures)))
        if len(hist) >= SLOW_FAILURES and not self._dup(f"R8:{src}", ts):
            return [Alert(
                "R8-SLOW-GUESSING", "medium",
                f"{len(hist)} failed authentications from source {src} within {SLOW_WINDOW_S // 60} minutes. Spread this thin they "
                f"stay under the {BURST_THRESHOLD}-in-{BURST_WINDOW_S}s burst rule, so a slow attacker would not trip it. "
                "Requests were denied.",
                [x[1] for x in hist], response="denied and rate limited", subject="unauthenticated", source=src)]
        return []

    def _skew_rule(self, seq: int, ts: float, d: dict[str, Any], src: str) -> list[Alert]:
        dev = str(d.get("device", "?"))
        try:
            skew = float(d.get("skew", 0.0))
        except (TypeError, ValueError):
            skew = 0.0
        hist = [x for x in self.stale.get(dev, []) if ts - x[0] <= BURST_WINDOW_S]
        hist.append((ts, seq, skew))
        self.stale[dev] = hist
        if len(self.stale) > self.max_tracked:
            self.stale.pop(next(iter(self.stale)))
        if len(hist) >= SKEW_WARN_COUNT and not self._dup(f"R9:{dev}", ts):
            offs = [x[2] for x in hist]
            return [Alert(
                "R9-CLOCK-SKEW", "low",
                f"{len(hist)} requests from {dev} were refused because their timestamps were outside the allowed "
                f"+/-{CLOCK_TOLERANCE_S}s window (offsets seen {min(offs):+.0f}s to {max(offs):+.0f}s from this node's clock). "
                "A device clock that has drifted looks like this, and so does replay of old traffic. Fix the device clock first.",
                [x[1] for x in hist], response="denied; no lockout", subject=dev,
                device=dev if dev in self.owner_of else "unknown",
                user=self.owner_of.get(dev, "unknown"), source=src)]
        return []

    def _dup(self, key: str, ts: float) -> bool:
        """Suppress repeat alerts for the same subject; the audit log keeps every attempt."""
        last = self.last_alert.get(key)
        if last is not None and ts - last < self.dedupe_s:
            return True
        self.last_alert[key] = ts
        if len(self.last_alert) > self.max_tracked:
            self.last_alert.pop(next(iter(self.last_alert)))
        return False
