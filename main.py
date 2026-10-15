"""
main.py
IDS entry point.
Starts all components, runs experiments, and reports metrics.

Usage:
    python main.py                  # run all experiments
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
    python main.py --scenario all
"""

import argparse
import logging
import sys
import time
import threading

# ── Bootstrap logging before any local imports ────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("ids.log"),
    ],
)
logger = logging.getLogger("ids.main")

# ── Local imports (order matters — schema has no deps) ────────────────────────
from schema       import Severity
from event_bus    import bus
from network_sensor import network_sensor
from host_sensor    import host_sensor
from correlation_engine import correlation_engine
from alert_manager  import alert_manager
from metrics        import metrics
from anomaly_detector import anomaly_detector
import attack_simulator as sim


# ── Wire the correlation engine to the bus ────────────────────────────────────
def _on_event(evt):
    correlation_engine.on_event(evt)


def _patch_alert_manager():
    """Monkey-patch AlertManager.raise_alert to also feed metrics."""
    original = alert_manager.raise_alert

    def patched(alert):
        original(alert)
        # Only record if alert actually got emitted
        h = alert_manager.get_history()
        if h and h[-1].alert_id == alert.alert_id:
            metrics.record_alert(alert)

    alert_manager.raise_alert = patched


# ── Experiment runner ──────────────────────────────────────────────────────────
def run_experiment(name: str, setup_fn, attack_fn,
                    expected_rule: str, expected_sev: str,
                    benign_warmup: float = 5.0,
                    reset_anomaly: bool = True):
    print(f"\n{'─'*60}")
    print(f"  EXPERIMENT: {name}")
    print(f"{'─'*60}")

    # Reset stateful components so experiments don't bleed into each other.
    # Anomaly baselines are optionally preserved so the statistical rule can fire.
    alert_manager.clear_history()
    network_sensor.reset_state()
    host_sensor.reset_state()
    if reset_anomaly:
        anomaly_detector.reset()
    with correlation_engine._lock:
        correlation_engine._window.clear()

    # 1. Benign warmup to establish baselines
    logger.info(f"[EXP] Warmup phase ({benign_warmup}s benign traffic)...")
    t = threading.Thread(target=sim.benign_traffic,
                          args=(benign_warmup, 1.0), daemon=True)
    t.start()
    t.join()

    # 2. Register ground truth AFTER warmup — window opens now, not during warmup
    gt = metrics.start_scenario(name, expected_rule, expected_sev)

    # 3. Optional setup
    if setup_fn:
        setup_fn()

    # 4. Run attack
    attack_fn()

    # 5. Give the engine a moment to process queued events
    time.sleep(1.5)

    # 6. Close the scenario window so subsequent alerts don't bleed in
    metrics.close_scenario()

    # 7. Report
    detected = "DETECTED" if gt.detected else "MISSED"
    latency  = f"{gt.detect_latency:.2f}s" if gt.detect_latency else "N/A"
    print(f"\n  [{name}] Result: {detected}  |  Latency: {latency}")


def start_ids():
    """Start all IDS components."""
    bus.subscribe(_on_event)
    bus.start()
    network_sensor.start()
    host_sensor.start()
    metrics.start_sampling()
    logger.info("IDS fully started.")


def stop_ids():
    """Gracefully stop all components."""
    bus.stop()
    network_sensor.stop()
    host_sensor.stop()
    metrics.stop_sampling()
    alert_manager.close()
    logger.info("IDS stopped.")


# ── Individual experiments ─────────────────────────────────────────────────────
EXPERIMENTS = {
    "brute_force": (
        "Brute-Force Login",
        None,
        lambda: sim.brute_force_login(attempts=20, interval=0.1),
        "BRUTE_FORCE_LOGIN",
        Severity.MEDIUM,
    ),
    "port_scan": (
        "Port Scan",
        None,
        lambda: sim.port_scan(n_ports=100, interval=0.02),
        "PORT_SCAN_DETECTED",
        Severity.HIGH,
    ),
    "replay": (
        "Replay Attack",
        None,
        lambda: sim.replay_attack(replays=4),
        "REPLAY_ATTACK",
        Severity.MEDIUM,
    ),
    "noise": (
        "Noise Injection (should NOT trigger alerts)",
        None,
        lambda: sim.noise_injection(duration=6.0),
        "__NO_MATCH__",   # sentinel — no alert expected, GT will always be MISSED
        Severity.CRITICAL,
    ),
    "sensor_failure": (
        "Sensor Failure + Attack (single-source, capped at HIGH)",
        None,
        lambda: sim.sensor_failure(sensor="network", duration=6.0),
        "BRUTE_FORCE_LOGIN",
        Severity.MEDIUM,
    ),
    "recon_bruteforce": (
        "Recon -> Brute-Force (multi-step CRITICAL)",
        None,
        lambda: sim.recon_then_bruteforce(),
        "RECONNAISSANCE_THEN_BRUTEFORCE",
        Severity.CRITICAL,
    ),
    "syn_flood": (
        "SYN Flood",
        None,
        lambda: sim.syn_flood(packets=200, rate=60.0),
        "SYN_FLOOD",
        Severity.HIGH,
    ),
    "credential_stuffing": (
        "Credential Stuffing (multiple usernames)",
        None,
        lambda: sim.credential_stuffing(),
        "CREDENTIAL_STUFFING",
        Severity.HIGH,
    ),
    "slow_scan": (
        "Slow Stealth Port Scan",
        None,
        lambda: sim.slow_port_scan(n_ports=12, interval=0.3),
        "PORT_SCAN_DETECTED",
        Severity.HIGH,
    ),
    "priv_esc": (
        "Privilege Escalation",
        None,
        lambda: sim.privilege_escalation(),
        "PRIVILEGE_ESCALATION",
        Severity.HIGH,
    ),
    "anomaly_corroboration": (
        "Statistical Anomaly Corroborated (two-source CRITICAL)",
        None,
        lambda: sim.anomaly_corroboration(),
        "STATISTICAL_ANOMALY_CORROBORATED",
        Severity.CRITICAL,
    ),
}


def run_all_experiments():
    for key, (name, setup, attack, rule, sev) in EXPERIMENTS.items():
        run_experiment(name, setup, attack, rule, sev, benign_warmup=4.0)
        time.sleep(1.0)


def main():
    parser = argparse.ArgumentParser(description="IDS Lab 4")
    parser.add_argument(
        "--scenario",
        choices=list(EXPERIMENTS.keys()) + ["all"],
        default="all",
        help="Which experiment to run (default: all)",
    )
    parser.add_argument(
        "--warmup",
        type=float,
        default=4.0,
        help="Benign warmup duration in seconds (default: 4)",
    )
    args = parser.parse_args()

    _patch_alert_manager()
    start_ids()

    print("\n" + "=" * 60)
    print("  IIIT-H SNS Lab 4 - Multi-Source IDS")
    print("=" * 60)

    try:
        if args.scenario == "all":
            run_all_experiments()
        else:
            name, setup, attack, rule, sev = EXPERIMENTS[args.scenario]
            run_experiment(name, setup, attack, rule, sev,
                            benign_warmup=args.warmup)

    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user.")
    finally:
        metrics.report()
        stop_ids()


if __name__ == "__main__":
    main()