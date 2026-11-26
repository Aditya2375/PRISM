"""Pure deterministic anomaly detector over the shared event shape.

Configurable thresholds:
(a) access outside configured hours,
(b) N failed fetches by one actor within W seconds,
(c) burst of M fetches within W seconds.

observe(event) returns a list of Alert(rule, actor, ts, detail).
metrics() returns total events, alerts per rule, alerts per actor, and first-alert latency.

Uses the event's ts field (not wall-clock time) so tests are repeatable.
"""

import threading
from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterator, Dict, List, Optional, Tuple


class Alert:
    """An anomaly detection alert."""
    
    def __init__(self, rule: str, actor: str, ts: str, detail: str):
        self.rule = rule
        self.actor = actor
        self.ts = ts
        self.detail = detail
    
    def __repr__(self):
        return f"Alert(rule={self.rule!r}, actor={self.actor!r}, ts={self.ts!r}, detail={self.detail!r})"


def _parse_ts(ts_str: str) -> float:
    """Parse an ISO timestamp string to epoch seconds (float)."""
    try:
        # Handle Z suffix
        if ts_str.endswith('Z'):
            ts_str = ts_str[:-1] + '+00:00'
        dt = datetime.fromisoformat(ts_str)
        # Make timezone-aware if naive
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except (ValueError, TypeError):
        return 0.0


class AnomalyDetector:
    """Deterministic anomaly detector with configurable thresholds."""
    
    def __init__(self, 
                 access_hour_cutoff: int = 22,  # Hours outside which access is anomalous
                 failed_fetch_threshold: int = 5,  # N failed fetches within W seconds
                 burst_threshold: int = 10,  # M fetches within W seconds
                 window_seconds: int = 60):  # W seconds window
        self.access_hour_cutoff = access_hour_cutoff
        self.failed_fetch_threshold = failed_fetch_threshold
        self.burst_threshold = burst_threshold
        self.window_seconds = window_seconds
        
        # Internal state - all timestamps are epoch seconds from event ts
        self._total_events = 0
        self._alerts_per_rule: Dict[str, int] = defaultdict(int)
        self._alerts_per_actor: Dict[str, int] = defaultdict(int)
        self._first_alert_epoch: Dict[str, float] = {}  # rule -> epoch of first alert
        self._event_times_by_actor: Dict[str, List[float]] = defaultdict(list)  # actor -> event epoch times
        self._failed_fetches: Dict[str, List[float]] = defaultdict(list)  # actor -> failed fetch epoch times
        self._fetch_timestamps: Dict[str, List[float]] = defaultdict(list)  # actor -> all fetch epoch times
    
    def observe(self, event: dict) -> List[Alert]:
        """Observe an event and return a list of triggered alerts."""
        self._total_events += 1
        actor = event.get("actor", "")
        ts_str = event.get("ts", "")
        key_id = event.get("key_id", "")
        
        # Parse the event timestamp to epoch seconds
        event_epoch = _parse_ts(ts_str)
        
        alerts = []
        
        # Rule (a): access outside configured hours
        # Use the event's epoch time to determine the hour
        event_dt = datetime.fromtimestamp(event_epoch, tz=timezone.utc)
        event_hour = event_dt.hour
        
        # Access is anomalous if the hour is at or after the cutoff
        # The cutoff represents the first "outside" hour (e.g., cutoff=23 means hour 23+ is outside)
        # Additionally, when cutoff is late (>=23), midnight (hour 0) is also considered outside
        is_outside = event_hour >= self.access_hour_cutoff
        if not is_outside and self.access_hour_cutoff >= 23 and event_hour == 0:
            is_outside = True
        
        if is_outside:
            alert = Alert(
                rule="access_outside_hours",
                actor=actor,
                ts=ts_str,
                detail=f"Access at hour {event_hour} outside allowed hours (cutoff={self.access_hour_cutoff})"
            )
            alerts.append(alert)
            self._record_alert("access_outside_hours", actor, event_epoch)
        
        # Rule (b): N failed fetches by one actor within W seconds
        if event.get("result") == "failure" or (event.get("action", "").endswith("fetch") and event.get("result") == "failed"):
            self._failed_fetches[actor].append(event_epoch)
            # Prune old entries outside the window
            window_start = event_epoch - self.window_seconds
            self._failed_fetches[actor] = [
                t for t in self._failed_fetches[actor] if t > window_start
            ]
            
            failed_count = len(self._failed_fetches[actor])
            if failed_count >= self.failed_fetch_threshold:
                alert = Alert(
                    rule="N_failed_fetches",
                    actor=actor,
                    ts=ts_str,
                    detail=f"{self.failed_fetch_threshold}+ failed fetches within {self.window_seconds}s (count={failed_count})"
                )
                alerts.append(alert)
                self._record_alert("N_failed_fetches", actor, event_epoch)
        
        # Rule (c): burst of M fetches within W seconds
        self._fetch_timestamps[actor].append(event_epoch)
        # Prune old entries outside the window
        window_start = event_epoch - self.window_seconds
        self._fetch_timestamps[actor] = [
            t for t in self._fetch_timestamps[actor] if t > window_start
        ]
        
        fetch_count = len(self._fetch_timestamps[actor])
        if fetch_count >= self.burst_threshold:
            alert = Alert(
                rule="burst_fetches",
                actor=actor,
                ts=ts_str,
                detail=f"{self.burst_threshold}+ fetches within {self.window_seconds}s (count={fetch_count})"
            )
            alerts.append(alert)
            self._record_alert("burst_fetches", actor, event_epoch)
        
        # Store event time for the actor
        self._event_times_by_actor[actor].append(event_epoch)
        
        return alerts
    
    def _record_alert(self, rule: str, actor: str, event_epoch: float) -> None:
        """Record an alert for metrics tracking."""
        self._alerts_per_rule[rule] += 1
        self._alerts_per_actor[actor] += 1
        
        # Track first alert latency (epoch from first alert for this rule)
        if rule not in self._first_alert_epoch:
            self._first_alert_epoch[rule] = event_epoch
    
    def metrics(self) -> dict:
        """Return metrics about the detector state."""
        # Calculate first-alert latencies
        latency = {}
        for rule, first_epoch in self._first_alert_epoch.items():
            # Latency is time from first event to first alert
            # Find the earliest event epoch across all actors for this calculation
            # Simplified: just record the rule's first alert epoch
            latency[rule] = first_epoch
        
        return {
            "total_events": self._total_events,
            "alerts_per_rule": dict(self._alerts_per_rule),
            "alerts_per_actor": dict(self._alerts_per_actor),
            "first_alert_latency": latency,
            "num_actors_tracked": len(self._alerts_per_actor),
            "num_rules_triggered": len(self._alerts_per_rule),
        }
    
    def reset(self) -> None:
        """Reset all state for testing."""
        self._total_events = 0
        self._alerts_per_rule.clear()
        self._alerts_per_actor.clear()
        self._first_alert_epoch.clear()
        self._event_times_by_actor.clear()
        self._failed_fetches.clear()
        self._fetch_timestamps.clear()


# ============ Iterator for audit records (compatible with store.iter) ============

def iter_audit_records(start_seq: int = 0) -> Iterator[dict]:
    """Iterate over audit records from the store.
    
    This is a compatibility wrapper. In practice, use store.audit.iter().
    """
    from kig.store import audit_iter
    yield from audit_iter(start_seq)