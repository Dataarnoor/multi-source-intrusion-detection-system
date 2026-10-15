"""
alert_manager.py
Generates, deduplicates, and logs alerts.
- Cooldown per (rule, entity) to prevent alert flooding.
- Enforces the critical security requirement at final output:
    CRITICAL only if source_count >= 2 OR rule is explicitly multi-step.
- Writes alerts to alerts.log (JSON-lines) and prints to stdout.
"""

import time
import threading
import logging
import json
from typing import Dict, List
from schema import Alert, Severity

logger = logging.getLogger("ids.alert_manager")

LOG_FILE = "alerts.log"

COOLDOWNS: Dict[str, float] = {
    Severity.INFO:     10.0,
    Severity.LOW:      15.0,
    Severity.MEDIUM:   20.0,
    Severity.HIGH:     30.0,
    Severity.CRITICAL: 45.0,
}

# Rules that are explicitly multi-step or multi-source and are allowed CRITICAL
# even from a single "sensor bundle"
CRITICAL_ALLOWED_RULES = {
    "RECONNAISSANCE_THEN_BRUTEFORCE",
    "BRUTE_FORCE_WITH_SCAN",
    "STATISTICAL_ANOMALY_CORROBORATED",
}


class AlertManager:
    def __init__(self):
        self._last_alert_time: Dict[str, float] = {}   # key -> last emit time
        self._lock = threading.Lock()
        self._alert_history: List[Alert] = []
        self._log_fh = None
        self._open_log()

    def _open_log(self):
        try:
            self._log_fh = open(LOG_FILE, "a", buffering=1)
        except Exception as e:
            logger.error(f"Cannot open alert log: {e}")

    def raise_alert(self, alert: Alert):
        """
        Final gate before emitting an alert.
        1. Enforce security requirement (CRITICAL cap).
        2. Deduplication / cooldown.
        3. Log and record.
        """
        # ── Security requirement enforcement ──────────────────────────────────
        if alert.severity == Severity.CRITICAL:
            if alert.rule_name not in CRITICAL_ALLOWED_RULES and alert.source_count < 2:
                # Downgrade — single source cannot be CRITICAL
                alert.severity = Severity.HIGH
                alert.description = "[DOWNGRADED: single source] " + alert.description

        # ── Cooldown / dedup ───────────────────────────────────────────────────
        entity = alert.metadata.get("entity", "global")
        key    = f"{alert.rule_name}:{entity}"
        now    = time.time()
        cooldown = COOLDOWNS.get(alert.severity, 30.0)

        with self._lock:
            last = self._last_alert_time.get(key, 0)
            if now - last < cooldown:
                return   # suppressed — within cooldown
            self._last_alert_time[key] = now
            self._alert_history.append(alert)

        # ── Emit ───────────────────────────────────────────────────────────────
        self._log_alert(alert)
        self._print_alert(alert)

    def _log_alert(self, alert: Alert):
        if self._log_fh:
            try:
                self._log_fh.write(json.dumps(alert.to_dict()) + "\n")
            except Exception as e:
                logger.error(f"Alert log write error: {e}")

    def _print_alert(self, alert: Alert):
        sev_colors = {
            Severity.INFO:     "\033[37m",    # white
            Severity.LOW:      "\033[34m",    # blue
            Severity.MEDIUM:   "\033[33m",    # yellow
            Severity.HIGH:     "\033[31m",    # red
            Severity.CRITICAL: "\033[35;1m",  # bright magenta
        }
        reset = "\033[0m"
        color = sev_colors.get(alert.severity, "")
        ts    = time.strftime("%H:%M:%S", time.localtime(alert.timestamp))
        print(
            f"{color}[{ts}] ALERT [{alert.severity}] [{alert.rule_name}] "
            f"score={alert.score:.1f} sources={alert.source_count}\n"
            f"  {alert.description}{reset}"
        )

    def get_history(self) -> List[Alert]:
        with self._lock:
            return list(self._alert_history)

    def get_counts_by_severity(self) -> Dict[str, int]:
        with self._lock:
            counts = {s: 0 for s in [Severity.INFO, Severity.LOW,
                                      Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]}
            for a in self._alert_history:
                counts[a.severity] = counts.get(a.severity, 0) + 1
            return counts

    def clear_history(self):
        with self._lock:
            self._alert_history.clear()
            self._last_alert_time.clear()

    def close(self):
        if self._log_fh:
            self._log_fh.close()


# Singleton
alert_manager = AlertManager()