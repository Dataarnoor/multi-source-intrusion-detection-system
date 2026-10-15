# IDS Lab 4 — Multi-Source Intrusion Detection System

## Setup

### Requirements
```
Python 3.9+
psutil
```

Install:
```bash
pip install psutil
```

---

## Project Structure

```
ids/
├── schema.py              # Unified JSON event + alert dataclasses
├── event_bus.py           # Thread-safe publish/subscribe event bus
├── network_sensor.py      # Flow-level network monitoring (port scan, SYN flood, replay)
├── host_sensor.py         # Login / process / file monitoring (brute-force, priv-esc)
├── anomaly_detector.py    # Statistical z-score anomaly detector (Welford running stats)
├── correlation_engine.py  # Sliding-window correlation engine with 9 detection rules
├── alert_manager.py       # Deduplication, cooldown, severity enforcement, JSON-lines log
├── attack_simulator.py    # 12 reproducible attack and benign scenarios
├── metrics.py             # Precision / Recall / F1 / latency / CPU + RAM reporting
├── main.py                # Entry point — wires all components, runs experiments
├── README.md
└── SECURITY.md
```

---

## Running

### Run all experiments
```bash
cd ids
python main.py
```

### Run a specific scenario
```bash
python main.py --scenario brute_force
python main.py --scenario port_scan
python main.py --scenario replay
python main.py --scenario noise
python main.py --scenario sensor_failure
python main.py --scenario recon_bruteforce
python main.py --scenario syn_flood
python main.py --scenario credential_stuffing
python main.py --scenario slow_scan
python main.py --scenario priv_esc
python main.py --scenario anomaly_corroboration
```

### Adjust warmup duration
```bash
python main.py --scenario brute_force --warmup 8
```

---

## Output Files

| File | Contents |
|------|----------|
| `alerts.log` | JSON-lines, one alert object per line |
| `ids.log`    | Full debug/info log from all components |

---

## Metrics Reported

- Precision, Recall, F1-score
- False Negative Rate
- Alert generation latency (avg + max)
- Peak and average CPU % and RAM, sampled every 0.5s throughout execution via background thread

---

## Attack Scenarios

| # | Scenario | Expected Rule | Min Severity | Result |
|---|----------|---------------|--------------|--------|
| 1 | Brute-force login | BRUTE_FORCE_LOGIN | MEDIUM | DETECTED (0.41s) |
| 2 | Port scan (fast) | PORT_SCAN_DETECTED | HIGH | DETECTED (0.19s) |
| 3 | Replay attack | REPLAY_ATTACK | MEDIUM | DETECTED (0.51s) |
| 4 | Noise injection | — (no alert expected) | — | CORRECT (no alert) |
| 5 | Sensor failure + attack | BRUTE_FORCE_LOGIN (single source, capped at HIGH) | MEDIUM | DETECTED (3.44s) |
| 6 | Recon then brute-force | RECONNAISSANCE_THEN_BRUTEFORCE | CRITICAL | DETECTED (2.26s) |
| 7 | SYN flood | SYN_FLOOD | HIGH | DETECTED (0.86s) |
| 8 | Credential stuffing | CREDENTIAL_STUFFING | HIGH | DETECTED (0.91s) |
| 9 | Slow stealth port scan | PORT_SCAN_DETECTED | HIGH | DETECTED (2.73s) |
| 10 | Privilege escalation | PRIVILEGE_ESCALATION | HIGH | DETECTED (0.61s) |
| 11 | Statistical anomaly corroborated | STATISTICAL_ANOMALY_CORROBORATED | CRITICAL | DETECTED (0.31s) |

Noise injection is excluded from TP/FN/FP counts — it is a true-negative scenario
with no expected alert, verified to produce zero alerts.

### Observed Metrics (sample run)

```
scenarios              10
true_positives         10
false_positives        7
false_negatives        0
total_alerts           17
precision              0.5882
recall                 1.0
f1_score               0.7407
false_negative_rate    0.0
avg_latency_s          1.215
max_latency_s          3.43
peak_cpu_percent       9.4
avg_cpu_percent        0.32
peak_memory_mb         23.96
avg_memory_mb          23.85
wall_time_s            106.9
```

### Note on False Positives

The 7 false positives are all legitimate co-firing alerts from compound attack scenarios,
not spurious detections:

- **Port scan**: fast scan rate crosses the SYN flood threshold, so SYN_FLOOD fires
  alongside PORT_SCAN_DETECTED.
- **Recon then brute-force**: PORT_SCAN_DETECTED, SYN_FLOOD, and BRUTE_FORCE_LOGIN all
  fire in addition to the two primary CRITICAL rules RECONNAISSANCE_THEN_BRUTEFORCE and
  BRUTE_FORCE_WITH_SCAN.
- **Anomaly corroboration**: BRUTE_FORCE_LOGIN fires alongside STATISTICAL_ANOMALY_CORROBORATED.

This is correct IDS behavior — a real system alerts on every observable attack signature
simultaneously. The metrics definition of FP here is "alert fired during a scenario window
that does not match that scenario's single primary expected rule", not "incorrect alert".

---

## Notes

- All traffic is simulated in-memory via inject_flow() — no real sockets or raw packets
  are used. This is consistent with the spec ("can be achieved using" scapy, sockets, etc.)
  and avoids requiring elevated permissions or external tools.
- Components run as threads on a single machine, communicating through a shared EventBus.
- State (sensor windows, correlation window, alert cooldowns) is reset between experiments.
  Anomaly baselines are preserved across experiments so the statistical detector has
  sufficient observations to build a meaningful baseline.
- Full IDS frameworks (Snort/Suricata) are not used, per assignment requirements.