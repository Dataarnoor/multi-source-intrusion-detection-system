"""
host_sensor.py
Monitors host-level events: login attempts, process executions, file accesses.
Generates synthetic log events (as required by the spec) and emits onto the bus.
"""

import time
import threading
import logging
from collections import defaultdict
from typing import Dict, List
from schema import Event, EventType, Severity
from event_bus import bus

logger = logging.getLogger("ids.host_sensor")

SOURCE = "host_sensor"

SUSPICIOUS_PROCESSES = {
    "nmap", "netcat", "nc", "wget", "curl", "bash", "sh", "python",
    "chmod", "chown", "sudo", "su", "passwd", "crontab",
    "tcpdump", "wireshark", "hydra", "metasploit", "sqlmap",
}

SENSITIVE_FILES = {
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/root/.ssh/authorized_keys", "/proc/net/tcp",
    "~/.bash_history", "/var/log/auth.log",
}


class UserState:
    def __init__(self):
        self.fail_times:    List[float] = []
        self.success_times: List[float] = []
        self.processes:     List[str]   = []


class HostSensor:
    WINDOW         = 60.0   # seconds
    BRUTE_THRESHOLD = 5     # failed logins within WINDOW to trigger alert

    def __init__(self):
        self._user_state: Dict[str, UserState] = defaultdict(UserState)
        self._lock = threading.Lock()
        self.enabled = True

    def start(self):
        logger.info("HostSensor started.")

    def stop(self):
        logger.info("HostSensor stopped.")

    # ── Public injection API (used by simulator and real log tailing) ──────────
    def record_login_attempt(self, username: str, success: bool,
                              src_ip: str = "127.0.0.1"):
        if not self.enabled:
            logger.warning("HostSensor is DOWN — dropping login event.")
            return

        now = time.time()
        etype = EventType.HOST_LOGIN_SUCCESS if success else EventType.HOST_LOGIN_FAIL
        sev   = Severity.INFO if success else Severity.LOW

        evt = Event(
            event_type  = etype,
            source      = SOURCE,
            severity    = sev,
            src_ip      = src_ip,
            username    = username,
            description = f"{'Successful' if success else 'Failed'} login for user '{username}' from {src_ip}",
            metadata    = {"success": success},
        )
        bus.publish(evt)

        with self._lock:
            state = self._user_state[username]
            if success:
                state.success_times.append(now)
                state.success_times = [t for t in state.success_times if now - t <= self.WINDOW]
            else:
                state.fail_times.append(now)
                state.fail_times = [t for t in state.fail_times if now - t <= self.WINDOW]

                n_fails = len(state.fail_times)
                # Emit brute-force alert at thresholds
                if n_fails == self.BRUTE_THRESHOLD or (n_fails > self.BRUTE_THRESHOLD and n_fails % 5 == 0):
                    self._emit_brute_force(username, src_ip, n_fails)

    def record_process_exec(self, username: str, process: str,
                             args: str = "", src_ip: str = "127.0.0.1"):
        if not self.enabled:
            return

        sev = Severity.LOW
        if any(proc in process.lower() for proc in SUSPICIOUS_PROCESSES):
            sev = Severity.MEDIUM

        evt = Event(
            event_type  = EventType.HOST_PROC_EXEC,
            source      = SOURCE,
            severity    = sev,
            src_ip      = src_ip,
            username    = username,
            process     = process,
            description = f"Process executed: '{process} {args}' by user '{username}'",
            metadata    = {"process": process, "args": args, "suspicious": sev == Severity.MEDIUM},
        )
        bus.publish(evt)

        with self._lock:
            self._user_state[username].processes.append(process)

        # Check for privilege escalation pattern
        with self._lock:
            recent_procs = self._user_state[username].processes[-10:]
        if any(p in ("sudo", "su", "chmod") for p in recent_procs):
            if any(p in SUSPICIOUS_PROCESSES - {"sudo","su","chmod"} for p in recent_procs):
                self._emit_priv_esc(username, src_ip, process)

    def record_file_access(self, username: str, filepath: str,
                            mode: str = "read", src_ip: str = "127.0.0.1"):
        if not self.enabled:
            return

        sev = Severity.MEDIUM if filepath in SENSITIVE_FILES else Severity.INFO
        evt = Event(
            event_type  = EventType.HOST_FILE_ACCESS,
            source      = SOURCE,
            severity    = sev,
            src_ip      = src_ip,
            username    = username,
            description = f"File {mode}: '{filepath}' by user '{username}'",
            metadata    = {"filepath": filepath, "mode": mode,
                           "sensitive": filepath in SENSITIVE_FILES},
        )
        bus.publish(evt)

    # ── Internal emitters ──────────────────────────────────────────────────────
    def _emit_brute_force(self, username: str, src_ip: str, n_fails: int):
        sev = Severity.HIGH if n_fails >= 10 else Severity.MEDIUM
        evt = Event(
            event_type  = EventType.HOST_LOGIN_FAIL,
            source      = SOURCE,
            severity    = sev,
            src_ip      = src_ip,
            username    = username,
            description = f"Brute-force detected: {n_fails} failed logins for '{username}' from {src_ip}",
            metadata    = {"fail_count": n_fails, "brute_force": True},
        )
        bus.publish(evt)
        logger.warning(f"[HOST] Brute-force: {username}@{src_ip} ({n_fails} fails)")

    def _emit_priv_esc(self, username: str, src_ip: str, process: str):
        evt = Event(
            event_type  = EventType.HOST_PRIV_ESC,
            source      = SOURCE,
            severity    = Severity.HIGH,
            src_ip      = src_ip,
            username    = username,
            process     = process,
            description = f"Privilege escalation pattern: user '{username}' ran suspicious priv commands",
            metadata    = {"trigger_process": process},
        )
        bus.publish(evt)
        logger.warning(f"[HOST] Privilege escalation pattern: {username}")

    def get_fail_count(self, username: str) -> int:
        with self._lock:
            state = self._user_state[username]
            now = time.time()
            return len([t for t in state.fail_times if now - t <= self.WINDOW])

    def get_all_fail_counts(self) -> Dict[str, int]:
        with self._lock:
            now = time.time()
            return {
                u: len([t for t in s.fail_times if now - t <= self.WINDOW])
                for u, s in self._user_state.items()
            }

    def reset_state(self):
        """Clear all per-user state between experiments."""
        with self._lock:
            self._user_state.clear()


# Singleton
host_sensor = HostSensor()