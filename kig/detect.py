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

    def as_data(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "explanation": self.explanation,
            "evidence": self.evidence,
            "response": self.response,
            "subject": self.subject,
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

    def observe(self, entry: dict[str, Any]) -> list[Alert]:
        t, seq, ts, d = entry["type"], entry["seq"], entry["ts"], entry["data"]
        alerts: list[Alert] = []
        actor = entry.get("actor", "?")

        if t in ("device.revoked", "device.lost"):
            self.removed_at[d["device"]] = seq
        if t in ("device.revoked", "device.lost") and d.get("admin_sibling"):
            alerts.append(
                Alert(
                    "R5-ADMIN-DEVICE-REVOKED-BY-SIBLING",
                    "critical",
                    f"An admin device ({d.get('device')}) of {d.get('user')} was removed by another device of the same admin ({actor}). "
                    "If this was not you, the acting device may be stolen: enrol a recovery device from the host and revoke it.",
                    [seq],
                    response="recorded; operator recovery (recover-admin) can add a new admin device",
                    subject=str(d.get("user")),
                )
            )
        elif t == "device.enrolled":
            self.first_device_ts.setdefault(d["user"], ts)
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
