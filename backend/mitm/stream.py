"""Server-Sent Events broadcaster for packet records."""
from __future__ import annotations
import json
import logging
import queue
import threading
import time
from typing import List, Optional

from .models import PacketRecord

log = logging.getLogger("mitm.stream")


class PacketStream:
    """
    Central hub. One producer queue -> many subscriber queues.
    Subscribers are SSE generators that pull from their own queue.
    """

    def __init__(self, max_queue: int = 5000):
        self._lock = threading.Lock()
        self._subscribers: List[queue.Queue] = []
        self._ring: List[PacketRecord] = []
        self._ring_max = max_queue
        self._paused = False

    # ---------- Producer side ----------
    def publish(self, record: PacketRecord) -> None:
        if self._paused:
            return
        with self._lock:
            self._ring.append(record)
            if len(self._ring) > self._ring_max:
                self._ring = self._ring[-self._ring_max:]
            subs = list(self._subscribers)
        for q in subs:
            try:
                q.put_nowait(record)
            except queue.Full:
                pass

    def publish_many(self, records: List[PacketRecord]) -> None:
        for r in records:
            self.publish(r)

    # ---------- Consumer side ----------
    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=2000)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            try:
                self._subscribers.remove(q)
            except ValueError:
                pass

    def recent(self, limit: int = 500) -> List[PacketRecord]:
        with self._lock:
            return list(self._ring[-limit:])

    def clear(self) -> None:
        with self._lock:
            self._ring.clear()

    # ---------- Pause / resume ----------
    def pause(self) -> None:
        self._paused = True

    def resume(self) -> None:
        self._paused = False

    def is_paused(self) -> bool:
        return self._paused

    # ---------- SSE generator ----------
    def sse_stream(self):
        """Yield SSE-formatted events. Caller wraps this in a Flask Response."""
        q = self.subscribe()
        try:
            # Send a hello so the client knows it's connected
            yield "event: hello\ndata: {}\n\n"
            while True:
                try:
                    rec = q.get(timeout=15)
                except queue.Empty:
                    # Heartbeat to keep proxies from closing the connection
                    yield ": keepalive\n\n"
                    continue
                payload = json.dumps(rec.to_dict(), default=str)
                yield f"event: packet\ndata: {payload}\n\n"
        finally:
            self.unsubscribe(q)


# Global stream (single-process Flask)
STREAM = PacketStream()