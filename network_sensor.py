"""
network_sensor.py
Captures/generates flow-level network metadata and emits Events onto the bus.
Uses scapy if available; otherwise falls back to socket-based flow simulation.
No deep packet inspection — only flow-level features.
"""

import time
import threading
import logging
import socket
import random
from collections import defaultdict
from typing import Dict, List, Tuple
from schema import Event, EventType, Severity
from event_bus import bus

logger = logging.getLogger("ids.network_sensor")

SOURCE = "network_sensor"


# ── Flow record ────────────────────────────────────────────────────────────────
class FlowRecord:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto):
        self.src_ip    = src_ip
        self.dst_ip    = dst_ip
        self.src_port  = src_port
        self.dst_port  = dst_port
        self.proto     = proto
        self.pkt_count = 0
        self.byte_count= 0
        self.start_time= time.time()
        self.last_time = time.time()

    def key(self):
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.proto)


# ── Per-IP state for scanning detection ───────────────────────────────────────
class IPState:
    def __init__(self):
        self.ports_touched: set = set()
        self.conn_times: List[float] = []
        self.syn_times:  List[float] = []


class NetworkSensor:
    WINDOW = 60.0          # seconds for per-IP aggregation window
    SYN_WINDOW = 5.0       # window for SYN rate

    def __init__(self):
        self._ip_state: Dict[str, IPState] = defaultdict(IPState)
        self._flows:    Dict[tuple, FlowRecord] = {}
        self._lock      = threading.Lock()
        self._running   = False
        self._seen_payloads: List[Tuple[str, float]] = []   # for replay detection
        self._simulate_thread: threading.Thread = None
        self.enabled = True

    # ── Public API ─────────────────────────────────────────────────────────────
    def start(self):
        self._running = True
        logger.info("NetworkSensor started (simulation mode).")

    def stop(self):
        self._running = False
        logger.info("NetworkSensor stopped.")

    def inject_flow(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                    proto: str = "TCP", pkt_count: int = 1, payload_hash: str = None):
        """Called by AttackSimulator or traffic generator to record a flow."""
        if not self.enabled:
            logger.warning("NetworkSensor is DOWN — dropping flow.")
            return

        now = time.time()
        key = (src_ip, dst_ip, src_port, dst_port, proto)

        with self._lock:
            if key not in self._flows:
                self._flows[key] = FlowRecord(src_ip, dst_ip, src_port, dst_port, proto)
            fr = self._flows[key]
            fr.pkt_count  += pkt_count
            fr.last_time   = now

            # Update per-IP state
            state = self._ip_state[src_ip]
            state.ports_touched.add(dst_port)
            state.conn_times.append(now)
            # prune old entries
            state.conn_times = [t for t in state.conn_times if now - t <= self.WINDOW]

            # Emit basic connection event
            evt = Event(
                event_type  = EventType.NET_CONNECTION,
                source      = SOURCE,
                severity    = Severity.INFO,
                src_ip      = src_ip,
                dst_ip      = dst_ip,
                src_port    = src_port,
                dst_port    = dst_port,
                protocol    = proto,
                description = f"Flow: {src_ip}:{src_port} -> {dst_ip}:{dst_port} [{proto}] pkts={pkt_count}",
                metadata    = {"pkt_count": pkt_count, "payload_hash": payload_hash},
            )
            bus.publish(evt)

            # Check for port scan
            self._check_port_scan(src_ip, dst_ip, dst_port, state)
            # Check for SYN flood
            if proto == "TCP":
                state.syn_times.append(now)
                state.syn_times = [t for t in state.syn_times if now - t <= self.SYN_WINDOW]
                self._check_syn_flood(src_ip, dst_ip, state)
            # Check replay
            if payload_hash:
                self._check_replay(src_ip, dst_ip, dst_port, payload_hash, now)

    # ── Internal detectors ─────────────────────────────────────────────────────
    def _check_port_scan(self, src_ip, dst_ip, dst_port, state: IPState):
        n_ports = len(state.ports_touched)
        if n_ports in (10, 20, 50, 100) or (n_ports > 100 and n_ports % 50 == 0):
            sev = Severity.MEDIUM if n_ports < 50 else Severity.HIGH
            evt = Event(
                event_type  = EventType.NET_PORT_SCAN,
                source      = SOURCE,
                severity    = sev,
                src_ip      = src_ip,
                dst_ip      = dst_ip,
                description = f"Port scan detected: {src_ip} touched {n_ports} ports on {dst_ip}",
                metadata    = {"ports_touched": n_ports,
                               "sample_ports": list(state.ports_touched)[:20]},
            )
            bus.publish(evt)
            logger.warning(f"[NET] Port scan: {src_ip} -> {n_ports} ports")

    def _check_syn_flood(self, src_ip, dst_ip, state: IPState):
        rate = len(state.syn_times)  # SYNs in last SYN_WINDOW seconds
        if rate >= 50:
            evt = Event(
                event_type  = EventType.NET_SYN_FLOOD,
                source      = SOURCE,
                severity    = Severity.HIGH,
                src_ip      = src_ip,
                dst_ip      = dst_ip,
                description = f"SYN flood: {src_ip} -> {dst_ip}, rate={rate}/s",
                metadata    = {"syn_rate": rate, "window_s": self.SYN_WINDOW},
            )
            bus.publish(evt)
            logger.warning(f"[NET] SYN flood: {src_ip} rate={rate}")

    def _check_replay(self, src_ip, dst_ip, dst_port, payload_hash, now):
        # Keep a sliding window of seen hashes
        self._seen_payloads = [(h, t) for h, t in self._seen_payloads if now - t <= 300]
        hashes = [h for h, _ in self._seen_payloads]
        if payload_hash in hashes:
            evt = Event(
                event_type  = EventType.NET_REPLAY,
                source      = SOURCE,
                severity    = Severity.MEDIUM,
                src_ip      = src_ip,
                dst_ip      = dst_ip,
                dst_port    = dst_port,
                description = f"Replay attack: duplicate payload hash {payload_hash} from {src_ip}",
                metadata    = {"payload_hash": payload_hash},
            )
            bus.publish(evt)
            logger.warning(f"[NET] Replay detected from {src_ip}: hash={payload_hash}")
        else:
            self._seen_payloads.append((payload_hash, now))

    def get_ip_port_count(self, src_ip: str) -> int:
        with self._lock:
            return len(self._ip_state[src_ip].ports_touched)

    def get_conn_rate(self, src_ip: str) -> float:
        with self._lock:
            state = self._ip_state[src_ip]
            now = time.time()
            recent = [t for t in state.conn_times if now - t <= self.WINDOW]
            return len(recent) / self.WINDOW

    def reset_state(self):
        """Clear all per-IP state between experiments."""
        with self._lock:
            self._ip_state.clear()
            self._flows.clear()
            self._seen_payloads.clear()


# Singleton
network_sensor = NetworkSensor()