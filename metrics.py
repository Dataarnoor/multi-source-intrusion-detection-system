"""
metrics.py
Collects evaluation metrics: Precision, Recall, F1, FNR,
alert latency, and CPU/memory usage (sampled continuously via background thread).

Usage:
    metrics = MetricsCollector()
    metrics.start_sampling()         # begin background CPU/RAM sampling
    metrics.start_scenario(...)
    metrics.record_alert(alert)      # called by alert_manager patch in main.py
    metrics.report()
"""

import time
import threading
import psutil
import os
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from schema import Alert, Severity

logger = logging.getLogger("ids.metrics")

# Severity rank for TP detection: alert is TP if severity >= expected
SEV_RANK = {
    Severity.INFO: 0, Severity.LOW: 1,
    Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4,
}


@dataclass
class GroundTruth:
    scenario:         str
    expected_rule:    str
    expected_min_sev: str
    # alerts observed strictly during this scenario window
    scenario_alerts:  List = field(default_factory=list)
    start_time:       float = field(default_factory=time.time)
    end_time:         Optional[float] = None
    detected:         bool  = False
    detect_latency:   Optional[float] = None


class MetricsCollector:
    SAMPLE_INTERVAL = 0.5   # seconds between CPU/RAM samples

    def __init__(self):
        self._ground_truths: List[GroundTruth] = []
        self._active_gt:     Optional[GroundTruth] = None
        self._all_alerts:    List[Tuple[float, Alert]] = []
        self._lock           = threading.Lock()
        self._proc           = psutil.Process(os.getpid())
        self._start_wall     = time.time()

        # Continuous resource sampling
        self._cpu_samples:   List[float] = []
        self._mem_samples:   List[float] = []
        self._sampling       = False
        self._sample_thread: Optional[threading.Thread] = None

    # ── Resource sampling ──────────────────────────────────────────────────────
    def start_sampling(self):
        """Start background thread that samples CPU and RAM every 0.5s."""
        self._sampling = True
        # Prime psutil so first real sample isn't 0
        self._proc.cpu_percent(interval=None)
        self._sample_thread = threading.Thread(
            target=self._sample_loop, daemon=True, name="MetricsSampler"
        )
        self._sample_thread.start()

    def stop_sampling(self):
        self._sampling = False

    def _sample_loop(self):
        while self._sampling:
            cpu = self._proc.cpu_percent(interval=None)
            mem = self._proc.memory_info().rss / 1024 / 1024
            with self._lock:
                self._cpu_samples.append(cpu)
                self._mem_samples.append(mem)
            time.sleep(self.SAMPLE_INTERVAL)

    # ── Scenario management ────────────────────────────────────────────────────
    def start_scenario(self, scenario: str, expected_rule: str,
                        expected_min_sev: str = Severity.MEDIUM) -> GroundTruth:
        # Close previous scenario window
        with self._lock:
            if self._active_gt and self._active_gt.end_time is None:
                self._active_gt.end_time = time.time()

        gt = GroundTruth(scenario=scenario,
                         expected_rule=expected_rule,
                         expected_min_sev=expected_min_sev)
        with self._lock:
            self._ground_truths.append(gt)
            self._active_gt = gt
        logger.debug("[METRICS] Scenario started: %s expecting rule=%s",
                     scenario, expected_rule)
        return gt

    def close_scenario(self):
        """Call after an experiment finishes to close the active window."""
        with self._lock:
            if self._active_gt:
                self._active_gt.end_time = time.time()

    def record_alert(self, alert: Alert):
        """Called after an alert is emitted by AlertManager."""
        now = time.time()
        with self._lock:
            self._all_alerts.append((now, alert))

            # Assign alert to the currently active scenario window
            if self._active_gt and self._active_gt.end_time is None:
                self._active_gt.scenario_alerts.append(alert)

            # Match alert to its own scenario's GT only
            for gt in self._ground_truths:
                if gt.detected:
                    continue
                # Only match alerts that arrived after this scenario started
                if now < gt.start_time:
                    continue
                # If scenario is closed, only match alerts before end_time
                if gt.end_time and now > gt.end_time:
                    continue
                if (alert.rule_name == gt.expected_rule and
                        SEV_RANK.get(alert.severity, 0) >=
                        SEV_RANK.get(gt.expected_min_sev, 0)):
                    gt.detected = True
                    gt.detect_latency = now - gt.start_time
                    logger.info(
                        "[METRICS] TP detected: %s latency=%.2fs",
                        gt.scenario.replace("\u2192", "->"),
                        gt.detect_latency,
                    )

    # ── Final report ───────────────────────────────────────────────────────────
    def report(self, print_output: bool = True) -> dict:
        self.stop_sampling()

        with self._lock:
            # Exclude sentinel scenarios (expected_rule == "__NO_MATCH__") from counts
            countable = [gt for gt in self._ground_truths if gt.expected_rule != "__NO_MATCH__"]
            total_scenarios = len(countable)
            tp = sum(1 for gt in countable if gt.detected)
            fn = total_scenarios - tp

            # FP: alerts fired during a scenario window that don't match that
            # scenario's expected rule. Sentinel scenarios contribute 0 FP.
            fp = 0
            for gt in countable:
                for a in gt.scenario_alerts:
                    if a.rule_name != gt.expected_rule:
                        fp += 1

            total_alerts = len(self._all_alerts)
            precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
            recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1        = (2 * precision * recall / (precision + recall)
                         if (precision + recall) > 0 else 0.0)
            fnr       = fn / (fn + tp) if (fn + tp) > 0 else 0.0

            latencies = [gt.detect_latency for gt in self._ground_truths
                         if gt.detect_latency is not None]
            avg_latency = sum(latencies) / len(latencies) if latencies else None
            max_latency = max(latencies) if latencies else None

            # Resource usage from continuous samples
            cpu_samples = list(self._cpu_samples)
            mem_samples = list(self._mem_samples)

        peak_cpu  = round(max(cpu_samples), 2)  if cpu_samples else 0.0
        avg_cpu   = round(sum(cpu_samples) / len(cpu_samples), 2) if cpu_samples else 0.0
        peak_mem  = round(max(mem_samples), 2)  if mem_samples else 0.0
        avg_mem   = round(sum(mem_samples) / len(mem_samples), 2) if mem_samples else 0.0
        wall_s    = round(time.time() - self._start_wall, 1)

        result = {
            "scenarios":            total_scenarios,
            "true_positives":       tp,
            "false_positives":      fp,
            "false_negatives":      fn,
            "total_alerts":         total_alerts,
            "precision":            round(precision, 4),
            "recall":               round(recall, 4),
            "f1_score":             round(f1, 4),
            "false_negative_rate":  round(fnr, 4),
            "avg_latency_s":        round(avg_latency, 3) if avg_latency else None,
            "max_latency_s":        round(max_latency, 3) if max_latency else None,
            "peak_cpu_percent":     peak_cpu,
            "avg_cpu_percent":      avg_cpu,
            "peak_memory_mb":       peak_mem,
            "avg_memory_mb":        avg_mem,
            "wall_time_s":          wall_s,
        }

        if print_output:
            print("\n" + "=" * 60)
            print("  IDS EVALUATION METRICS")
            print("=" * 60)
            for k, v in result.items():
                print(f"  {k:<30} {v}")
            print("=" * 60 + "\n")

        return result

    def clear(self):
        with self._lock:
            self._ground_truths.clear()
            self._all_alerts.clear()
            self._active_gt = None


# Singleton
metrics = MetricsCollector()