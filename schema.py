"""
schema.py - Unified JSON-based event schema for all IDS components.
All sensors, detectors, and the correlation engine use this format.
"""

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any
import json

# ── Event Types ────────────────────────────────────────────────────────────────
class EventType:
    # Network events
    NET_CONNECTION     = "net_connection"
    NET_PORT_SCAN      = "net_port_scan"
    NET_SYN_FLOOD      = "net_syn_flood"
    NET_REPLAY         = "net_replay"

    # Host events
    HOST_LOGIN_FAIL    = "host_login_fail"
    HOST_LOGIN_SUCCESS = "host_login_success"
    HOST_PROC_EXEC     = "host_proc_exec"
    HOST_FILE_ACCESS   = "host_file_access"
    HOST_PRIV_ESC      = "host_priv_esc"

    # Sensor health
    SENSOR_DOWN        = "sensor_down"
    SENSOR_UP          = "sensor_up"

    # Anomaly
    ANOMALY_STAT       = "anomaly_statistical"


# ── Severity Levels ────────────────────────────────────────────────────────────
class Severity:
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

    _order = [INFO, LOW, MEDIUM, HIGH, CRITICAL]

    @classmethod
    def rank(cls, sev: str) -> int:
        try:
            return cls._order.index(sev)
        except ValueError:
            return 0

    @classmethod
    def max(cls, a: str, b: str) -> str:
        return a if cls.rank(a) >= cls.rank(b) else b


# ── Core Event Dataclass ───────────────────────────────────────────────────────
@dataclass
class Event:
    event_id:    str            = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:   float          = field(default_factory=time.time)
    event_type:  str            = ""
    source:      str            = ""          # "network_sensor" | "host_sensor" | "ids_engine"
    severity:    str            = Severity.INFO
    src_ip:      Optional[str]  = None
    dst_ip:      Optional[str]  = None
    src_port:    Optional[int]  = None
    dst_port:    Optional[int]  = None
    protocol:    Optional[str]  = None
    username:    Optional[str]  = None
    process:     Optional[str]  = None
    description: str            = ""
    metadata:    Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, d: dict) -> "Event":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    @classmethod
    def from_json(cls, s: str) -> "Event":
        return cls.from_dict(json.loads(s))


# ── Alert Dataclass ────────────────────────────────────────────────────────────
@dataclass
class Alert:
    alert_id:      str            = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:     float          = field(default_factory=time.time)
    rule_name:     str            = ""
    severity:      str            = Severity.INFO
    score:         float          = 0.0
    description:   str            = ""
    source_count:  int            = 1       # how many independent sources contributed
    contributing_events: list     = field(default_factory=list)
    metadata:      Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
