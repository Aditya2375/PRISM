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
        }


@dataclass
class Detector:
    """Keeps a small amount of derived state; fed one audit entry at a time."""

    removed_at: dict[str, int] = field(default_factory=dict)  # device -> seq of revoke/lost
    failures: dict[str, list[tuple[float, int]]] = field(default_factory=dict)
    first_device_ts: dict[str, float] = field(default_factory=dict)
    max_tracked: int = 4096
    last_alert: dict[str, float] = field(default_factory=dict)
    dedupe_s: int = 60
    service: str = "unknown"
    owner_of: dict[str, str] = field(default_factory=dict)  # device -> user, from device.enrolled entries

    def observe(self, entry: dict[str, Any]) -> list[Alert]:
        t, seq, ts, d = entry["type"], entry["seq"], entry["ts"], entry["data"]
        alerts: list[Alert] = []
        actor = entry.get("actor", "?")
        src = d.get("source") if isinstance(d.get("source"), str) and d.get("source") else "unknown"
        alerts = self._observe(entry, t, seq, ts, d, actor, src)
        for a in alerts:
            a.service, a.event = self.service, t
            if a.source == "unknown":
                a.source = src
            if a.actor == "unknown" and actor != "?":
                a.actor = str(actor)
            if a.user == "unknown" and a.device != "unknown":
                a.user = self.owner_of.get(a.device, "unknown")
        return alerts

    def _observe(self, entry: dict[str, Any], t: str, seq: int, ts: float, d: dict[str, Any], actor: str, src: str) -> list[Alert]:
        alerts: list[Alert] = []

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
            key = f"{d.get('device', '?')}@{d.get('source')}"
            hist = [x for x in self.failures.get(key, []) if ts - x[0] <= BURST_WINDOW_S]
            hist.append((ts, seq))
            self.failures[key] = hist
            if len(self.failures) > self.max_tracked:
                self.failures.pop(next(iter(self.failures)))
            if len(hist) >= BURST_THRESHOLD:
                alerts.append(
                    Alert(
                        "R3-AUTH-FAILURE-BURST",
                        "high",
                        f"{len(hist)} failed authentications claiming '{key}' within "
                        f"{BURST_WINDOW_S}s from one source. Requests were denied; nobody is locked out.",
                        [s for _, s in hist],
                        response="denied and rate limited",
                        subject=key.split("@")[0],
                        device=key.split("@")[0],
                        source=str(d.get("source") or "unknown"),
                    )
                )
                self.failures[key] = []
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

    def _dup(self, key: str, ts: float) -> bool:
        """Suppress repeat alerts for the same subject; the audit log keeps every attempt."""
        last = self.last_alert.get(key)
        if last is not None and ts - last < self.dedupe_s:
            return True
        self.last_alert[key] = ts
        if len(self.last_alert) > self.max_tracked:
            self.last_alert.pop(next(iter(self.last_alert)))
        return False
