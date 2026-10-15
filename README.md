# Multi-Source Intrusion Detection System

A Python IDS prototype that correlates simulated host activity and network flows using a threaded publish/subscribe event bus, nine sliding-window detection rules, and statistical anomaly detection.

Developed as part of System and Network Security coursework at IIIT Hyderabad.

## Highlights

- Correlates login failures, process activity, file events, and network-flow metadata.
- Uses online mean/variance statistics and z-scores to identify anomalous activity.
- Raises critical alerts for corroborated evidence or a confirmed multi-step attack; caps other single-source alerts at high severity.
- Deduplicates alerts and applies cooldowns to reduce repeated notifications.
- Includes 11 reproducible scenarios: 10 attacks or failure-with-attack scenarios and one benign noise scenario.
- Reports precision, recall, F1, false negative rate, alert latency, CPU, and memory usage.

## Architecture

```text
Simulated network flows ----> NetworkSensor --+
                                             |
Simulated host activity ----> HostSensor -----+--> EventBus
                                                    |
                                             CorrelationEngine
                                               |          |
                                               |    AnomalyDetector
                                               |          |
                                               |    anomaly events
                                               |    back to EventBus
                                               v
                                           AlertManager
                                               |
                                        JSON-lines alerts

Metrics collects emitted alerts, scenario ground truth, and resource samples.
```

Events are injected in memory. The demo does not capture live packets or read operating-system audit logs.

## Quick start

Requires Python 3.9+ and `psutil`.

```bash
git clone https://github.com/Dataarnoor/multi-source-intrusion-detection-system.git
cd multi-source-intrusion-detection-system
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py --scenario brute_force
```

On Windows, activate the environment with `.venv\Scripts\activate`.

Run all scenarios:

```bash
python main.py
```

The full suite takes approximately two minutes, depending on the machine. To change warmup for an individual scenario:

```bash
python main.py --scenario port_scan --warmup 8
```

## Scenarios

| Argument | Demonstration |
| --- | --- |
| `brute_force` | Repeated failed logins |
| `port_scan` | Fast scan across destination ports |
| `replay` | Repeated payload observed from another source |
| `noise` | Benign traffic that should produce no alert |
| `sensor_failure` | Detection with one sensor unavailable |
| `recon_bruteforce` | Reconnaissance followed by failed logins |
| `syn_flood` | High rate of simulated SYN connections |
| `credential_stuffing` | Failed logins across distinct usernames |
| `slow_scan` | Scan spread over time |
| `priv_esc` | Suspicious process activity after privilege changes |
| `anomaly_corroboration` | Statistical anomaly supported by host evidence |

## Evaluation

The original project documentation records the following sample full-suite run:

| Metric | Recorded value |
| --- | --- |
| Attack scenarios detected | 10 / 10 |
| Recall / false negative rate | 100% / 0% |
| Average alert latency | 1.215 seconds |
| Average CPU / memory | 0.32% / 23.85 MB |
| Precision / F1 | 0.5882 / 0.7407 |

These are historical results on the original machine, not guaranteed performance. The evaluator counts additional alerts that do not match a scenario's primary expected rule as false positives; compound scenarios can trigger multiple legitimate rules. The benign noise scenario is excluded from attack TP/FN counts. A single-scenario run does not reproduce full-suite measurements.

Running the demo generates `ids.log` and `alerts.log` locally. Both are excluded from Git.

## Source map

| File | Responsibility |
| --- | --- |
| `schema.py` | Event and alert data models |
| `event_bus.py` | Thread-safe publish/subscribe dispatch |
| `network_sensor.py`, `host_sensor.py` | Sensor state and event generation |
| `correlation_engine.py` | Nine detection rules and sliding windows |
| `anomaly_detector.py` | Statistical baselines and anomaly events |
| `alert_manager.py` | Severity enforcement, cooldowns, and logging |
| `attack_simulator.py` | Reproducible event scenarios |
| `metrics.py` | Detection and resource measurements |
| `main.py` | Component startup and experiment execution |

See [security design](SECURITY.md) and the [original coursework README](docs/original-readme.md) for further details. The original documents preserve the project's recorded analysis and measurements. This repository is an educational prototype; live telemetry adapters and operational evaluation would be needed for deployment.
