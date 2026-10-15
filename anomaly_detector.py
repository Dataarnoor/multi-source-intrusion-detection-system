"""
anomaly_detector.py
Lightweight statistical anomaly detector.
Maintains running mean/std for configurable features and emits anomaly events
when z-score exceeds a threshold.
"""

import math
import time
import threading
import logging
from collections import deque, defaultdict
from typing import Dict, Deque
from schema import Event, EventType, Severity
from event_bus import bus

logger = logging.getLogger("ids.anomaly")

SOURCE = "anomaly_detector"
EPSILON = 1e-6


class RunningStats:
    """Welford online mean/variance."""
    def __init__(self, window: int = 200):
        self._window: Deque[float] = deque(maxlen=window)
        self._lock = threading.Lock()

    def update(self, value: float):
        with self._lock:
            self._window.append(value)

    def mean(self) -> float:
        with self._lock:
            if not self._window:
                return 0.0
            return sum(self._window) / len(self._window)

    def std(self) -> float:
        with self._lock:
            n = len(self._window)
            if n < 2:
                return 0.0
            mu = sum(self._window) / n
            variance = sum((x - mu) ** 2 for x in self._window) / n
            return math.sqrt(variance)

    def z_score(self, value: float) -> float:
        mu  = self.mean()
        std = self.std()
        return abs(value - mu) / (std + EPSILON)

    def has_baseline(self) -> bool:
        with self._lock:
            return len(self._window) >= 20


class AnomalyDetector:
    """
    Monitors the following features per source entity (IP or username):
        - failed_login_rate   (per host sensor)
        - port_scan_rate      (per network sensor)
        - connection_rate     (per network sensor)
    """

    Z_THRESHOLD = 3.0    # flag if z-score exceeds this

    def __init__(self):
        # Feature -> entity_id -> RunningStats
        self._stats: Dict[str, Dict[str, RunningStats]] = defaultdict(lambda: defaultdict(RunningStats))
        self._lock = threading.Lock()
        self._last_alert: Dict[str, float] = {}
        self._cooldown = 30.0   # seconds between repeat anomaly alerts

    def observe(self, feature: str, entity_id: str, value: float, context: dict = None):
        """
        Record a new observation for (feature, entity_id).
        Emits an ANOMALY_STAT event if z-score crosses threshold.
        """
        stats = self._stats[feature][entity_id]
        z = stats.z_score(value) if stats.has_baseline() else 0.0
        stats.update(value)

        if stats.has_baseline() and z >= self.Z_THRESHOLD:
            cooldown_key = f"{feature}:{entity_id}"
            now = time.time()
            with self._lock:
                last = self._last_alert.get(cooldown_key, 0)
                if now - last < self._cooldown:
                    return
                self._last_alert[cooldown_key] = now

            severity = Severity.MEDIUM if z < 5.0 else Severity.HIGH

            evt = Event(
                event_type  = EventType.ANOMALY_STAT,
                source      = SOURCE,
                severity    = severity,
                src_ip      = entity_id if entity_id != "unknown" else None,
                description = (
                    f"Statistical anomaly: feature='{feature}' entity='{entity_id}' "
                    f"value={value:.2f} z={z:.2f} (threshold={self.Z_THRESHOLD})"
                ),
                metadata    = {
                    "feature":   feature,
                    "entity_id": entity_id,
                    "value":     value,
                    "z_score":   round(z, 3),
                    "mean":      round(stats.mean(), 3),
                    "std":       round(stats.std(), 3),
                    **(context or {}),
                },
            )
            bus.publish(evt)
            logger.warning(
                f"[ANOMALY] {feature}@{entity_id}: value={value:.2f} z={z:.2f}"
            )

    def reset(self, feature: str = None, entity_id: str = None):
        with self._lock:
            if feature and entity_id:
                self._stats[feature].pop(entity_id, None)
            elif feature:
                self._stats.pop(feature, None)
            else:
                self._stats.clear()


# Singleton
anomaly_detector = AnomalyDetector()