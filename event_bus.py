"""
event_bus.py - Thread-safe publish/subscribe event bus.
All components put events here; the correlation engine reads from it.
"""

import queue
import threading
import logging
from typing import Callable, List
from schema import Event

logger = logging.getLogger("ids.event_bus")


class EventBus:
    def __init__(self):
        self._queue: queue.Queue = queue.Queue()
        self._subscribers: List[Callable[[Event], None]] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: threading.Thread = None

    def subscribe(self, callback: Callable[[Event], None]):
        with self._lock:
            self._subscribers.append(callback)

    def publish(self, event: Event):
        self._queue.put(event)

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._dispatch_loop, daemon=True, name="EventBus")
        self._thread.start()
        logger.info("EventBus started.")

    def stop(self):
        self._running = False
        self._queue.put(None)  # sentinel
        if self._thread:
            self._thread.join(timeout=3)
        logger.info("EventBus stopped.")

    def _dispatch_loop(self):
        while self._running:
            try:
                event = self._queue.get(timeout=0.5)
                if event is None:
                    break
                with self._lock:
                    callbacks = list(self._subscribers)
                for cb in callbacks:
                    try:
                        cb(event)
                    except Exception as e:
                        logger.error(f"Subscriber error: {e}")
            except queue.Empty:
                continue


# Singleton bus shared across the process
bus = EventBus()
