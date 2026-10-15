"""
correlation_engine.py
Core detection logic.
- Maintains a sliding time-window of recent events per entity (IP / username).
- Implements >= 6 non-trivial rule-based detectors.
- Enforces the critical security requirement:
    CRITICAL severity only if >= 2 independent sources agree within the window,
    OR a strong multi-step pattern is detected.
- Feeds anomaly observations to the AnomalyDetector.
"""

import time
import threading
import logging
from collections import defaultdict, deque
from typing import Dict, Deque, List, Tuple
from schema import Event, EventType, Severity, Alert
from alert_manager import alert_manager
from anomaly_detector import anomaly_detector

logger = logging.getLogger("ids.correlation")

WINDOW = 120.0   # seconds — sliding window for correlation


# ── Helpers ────────────────────────────────────────────────────────────────────
def _entity(evt: Event) -> str:
    """Primary entity identifier: prefer src_ip, fall back to username."""
    return evt.src_ip or evt.username or "unknown"


# ── Rule definitions ───────────────────────────────────────────────────────────
# Each rule is a dict consumed by _apply_rules().

RULES = [
    {
        "name":        "BRUTE_FORCE_LOGIN",
        "description": "Multiple failed logins from the same source",
        "event_types": {EventType.HOST_LOGIN_FAIL},
        "min_events":  5,
        "window":      60.0,
        "base_score":  40.0,
        "per_event_score": 5.0,
        "base_severity":   Severity.MEDIUM,
    },
    {
        "name":        "PORT_SCAN_DETECTED",
        "description": "Host touched many distinct ports in a short window",
        "event_types": {EventType.NET_PORT_SCAN},
        "min_events":  1,
        "window":      60.0,
        "base_score":  35.0,
        "per_event_score": 0.0,
        "base_severity":   Severity.HIGH,
    },
    {
        "name":        "CREDENTIAL_STUFFING",
        "description": "Login failures against multiple distinct usernames from same IP",
        "event_types": {EventType.HOST_LOGIN_FAIL},
        "min_events":  3,
        "window":      60.0,
        "base_score":  45.0,
        "per_event_score": 5.0,
        "base_severity":   Severity.HIGH,
        "distinct_field":  "username",   # must be distinct
        "distinct_min":    3,
    },
    {
        "name":        "RECONNAISSANCE_THEN_BRUTEFORCE",
        "description": "Port scan followed by brute-force login — multi-step attack",
        "multi_step":  True,
        "steps": [
            {"event_type": EventType.NET_PORT_SCAN,   "window_back": 120.0},
            {"event_type": EventType.HOST_LOGIN_FAIL,  "min_count": 3},
        ],
        "base_score":  75.0,
        "base_severity":   Severity.CRITICAL,   # multi-step → allowed to be CRITICAL
        "force_critical":  True,
    },
    {
        "name":        "REPLAY_ATTACK",
        "description": "Replay of previously seen payload detected",
        "event_types": {EventType.NET_REPLAY},
        "min_events":  1,
        "window":      120.0,
        "base_score":  30.0,
        "per_event_score": 10.0,
        "base_severity":   Severity.MEDIUM,
    },
    {
        "name":        "SYN_FLOOD",
        "description": "High rate of SYN packets from a single source",
        "event_types": {EventType.NET_SYN_FLOOD},
        "min_events":  1,
        "window":      30.0,
        "base_score":  50.0,
        "per_event_score": 0.0,
        "base_severity":   Severity.HIGH,
    },
    {
        "name":        "PRIVILEGE_ESCALATION",
        "description": "Privilege escalation pattern detected on host",
        "event_types": {EventType.HOST_PRIV_ESC},
        "min_events":  1,
        "window":      120.0,
        "base_score":  60.0,
        "per_event_score": 0.0,
        "base_severity":   Severity.HIGH,
    },
    {
        "name":        "BRUTE_FORCE_WITH_SCAN",
        "description": "Brute-force corroborated by network scan — two-source CRITICAL",
        "multi_source": True,
        "required_types": [
            {"source": "host_sensor",    "event_type": EventType.HOST_LOGIN_FAIL, "min": 5},
            {"source": "network_sensor", "event_type": EventType.NET_PORT_SCAN,   "min": 1},
        ],
        "window":      120.0,
        "base_score":  80.0,
        "base_severity":   Severity.CRITICAL,   # two sources → CRITICAL allowed
    },
    {
        "name":        "STATISTICAL_ANOMALY_CORROBORATED",
        "description": "Statistical anomaly corroborated by a rule-based signal — two-source CRITICAL",
        "multi_source": True,
        "required_types": [
            {"source": "anomaly_detector", "event_type": EventType.ANOMALY_STAT,       "min": 1},
            {"source": "host_sensor",      "event_type": EventType.HOST_LOGIN_FAIL,     "min": 3},
        ],
        "window":      120.0,
        "base_score":  70.0,
        "base_severity":   Severity.CRITICAL,
    },
]


# ── Correlation Engine ─────────────────────────────────────────────────────────
class CorrelationEngine:
    def __init__(self):
        # entity -> deque of (Event,)
        self._window: Dict[str, Deque[Event]] = defaultdict(lambda: deque())
        self._lock = threading.Lock()

    def on_event(self, evt: Event):
        """Called by EventBus subscriber on every new event."""
        entity = _entity(evt)
        now = evt.timestamp

        with self._lock:
            dq = self._window[entity]
            dq.append(evt)
            # Prune events outside the maximum window
            while dq and now - dq[0].timestamp > WINDOW:
                dq.popleft()
            recent = list(dq)

        # Feed anomaly detector
        self._feed_anomaly(evt, entity)

        # Apply all rules
        for rule in RULES:
            self._apply_rule(rule, entity, recent, evt)

    # ── Anomaly feature feeding ────────────────────────────────────────────────
    def _feed_anomaly(self, evt: Event, entity: str):
        if evt.event_type == EventType.HOST_LOGIN_FAIL:
            # Observe rolling fail count for this entity
            with self._lock:
                dq = self._window[entity]
                count = sum(1 for e in dq
                            if e.event_type == EventType.HOST_LOGIN_FAIL
                            and evt.timestamp - e.timestamp <= 60.0)
            anomaly_detector.observe("failed_login_rate", entity, float(count))

        elif evt.event_type == EventType.NET_PORT_SCAN:
            meta = evt.metadata or {}
            ports = meta.get("ports_touched", 1)
            anomaly_detector.observe("port_scan_rate", entity, float(ports))

        elif evt.event_type == EventType.NET_CONNECTION:
            with self._lock:
                dq = self._window[entity]
                count = sum(1 for e in dq
                            if e.event_type == EventType.NET_CONNECTION
                            and evt.timestamp - e.timestamp <= 60.0)
            anomaly_detector.observe("connection_rate", entity, float(count))

    # ── Rule dispatcher ────────────────────────────────────────────────────────
    def _apply_rule(self, rule: dict, entity: str, recent: List[Event], trigger: Event):
        if rule.get("multi_step"):
            self._apply_multistep_rule(rule, entity, recent, trigger)
        elif rule.get("multi_source"):
            self._apply_multisource_rule(rule, entity, recent, trigger)
        else:
            self._apply_simple_rule(rule, entity, recent, trigger)

    # ── Simple rule ────────────────────────────────────────────────────────────
    def _apply_simple_rule(self, rule: dict, entity: str, recent: List[Event], trigger: Event):
        etypes = rule["event_types"]
        if trigger.event_type not in etypes:
            return

        window   = rule["window"]
        min_evt  = rule["min_events"]
        now      = trigger.timestamp

        matching = [e for e in recent
                    if e.event_type in etypes and now - e.timestamp <= window]

        # Optional distinct field check
        if "distinct_field" in rule:
            field    = rule["distinct_field"]
            distinct = {getattr(e, field, None) for e in matching if getattr(e, field, None)}
            if len(distinct) < rule.get("distinct_min", 1):
                return

        if len(matching) < min_evt:
            return

        score = rule["base_score"] + len(matching) * rule.get("per_event_score", 0.0)
        sev   = rule["base_severity"]

        # Enforce core security requirement:
        # Only one source contributing → cap at HIGH
        sources = {e.source for e in matching}
        if len(sources) < 2 and sev == Severity.CRITICAL:
            sev = Severity.HIGH

        alert_manager.raise_alert(Alert(
            rule_name   = rule["name"],
            severity    = sev,
            score       = score,
            description = rule["description"] + f" [entity={entity}, count={len(matching)}]",
            source_count= len(sources),
            contributing_events=[e.event_id for e in matching[-10:]],
            metadata    = {"entity": entity, "event_count": len(matching),
                           "sources": list(sources)},
        ))

    # ── Multi-step rule ────────────────────────────────────────────────────────
    def _apply_multistep_rule(self, rule: dict, entity: str, recent: List[Event], trigger: Event):
        steps  = rule["steps"]
        now    = trigger.timestamp

        # Check step 0 — must exist in window
        step0 = steps[0]
        s0_matches = [e for e in recent
                      if e.event_type == step0["event_type"]
                      and now - e.timestamp <= step0.get("window_back", WINDOW)]
        if not s0_matches:
            return

        # Check step 1 — must have min_count matches
        step1 = steps[1]
        s1_min = step1.get("min_count", 1)
        s1_matches = [e for e in recent
                      if e.event_type == step1["event_type"]
                      and now - e.timestamp <= WINDOW]
        if len(s1_matches) < s1_min:
            return

        # Both steps confirmed — multi-step → CRITICAL is allowed
        score = rule["base_score"]
        sev   = Severity.CRITICAL if rule.get("force_critical") else rule["base_severity"]

        all_events = s0_matches + s1_matches
        sources = {e.source for e in all_events}

        alert_manager.raise_alert(Alert(
            rule_name   = rule["name"],
            severity    = sev,
            score       = score,
            description = rule["description"] + f" [entity={entity}]",
            source_count= len(sources),
            contributing_events=[e.event_id for e in all_events[-10:]],
            metadata    = {
                "entity":  entity,
                "step0_count": len(s0_matches),
                "step1_count": len(s1_matches),
                "sources": list(sources),
            },
        ))

    # ── Multi-source rule ──────────────────────────────────────────────────────
    def _apply_multisource_rule(self, rule: dict, entity: str, recent: List[Event], trigger: Event):
        window   = rule["window"]
        now      = trigger.timestamp
        req      = rule["required_types"]

        matched_groups = []
        for req_item in req:
            grp = [e for e in recent
                   if e.source == req_item["source"]
                   and e.event_type == req_item["event_type"]
                   and now - e.timestamp <= window]
            if len(grp) < req_item.get("min", 1):
                return      # requirement not satisfied
            matched_groups.append(grp)

        # All requirements satisfied — two independent sources confirm → CRITICAL OK
        all_events = [e for grp in matched_groups for e in grp]
        sources = {e.source for e in all_events}

        score = rule["base_score"]
        sev   = rule["base_severity"]   # CRITICAL allowed here

        alert_manager.raise_alert(Alert(
            rule_name   = rule["name"],
            severity    = sev,
            score       = score,
            description = rule["description"] + f" [entity={entity}]",
            source_count= len(sources),
            contributing_events=[e.event_id for e in all_events[-10:]],
            metadata    = {
                "entity":  entity,
                "sources": list(sources),
                "group_counts": [len(g) for g in matched_groups],
            },
        ))


# Singleton
correlation_engine = CorrelationEngine()