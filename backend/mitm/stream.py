"""SSE broadcaster with three event kinds: packet, flow, arp."""
from __future__ import annotations
import json
import queue
import threading
from typing import List

from .models import PacketRecord, Flow

RING_MAX = 5000


class PacketStream:
    def __init__(self):
        self._lock = threading.Lock()
        self._subscribers: List[queue.Queue] = []
        self._ring: List[PacketRecord] = []
        self._paused = False

    # ---------- publish ----------
    def publish(self, record: PacketRecord) -> None:
        if self._paused:
            return
        with self._lock:
            self._ring.append(record)
            if len(self._ring) > RING_MAX:
                self._ring = self._ring[-RING_MAX:]
            subs = list(self._subscribers)
        for q in subs:
            self._push(q, "packet", record.to_dict())

    def publish_flow(self, flow: dict) -> None:
        with self._lock:
            subs = list(self._subscribers)
        for q in subs:
            self._push(q, "flow", flow)

    def publish_arp(self, stats: dict) -> None:
        with self._lock:
            subs = list(self._subscribers)
        for q in subs:
            self._push(q, "arp", stats)

    def _push(self, q: queue.Queue, event: str, payload: dict) -> None:
        try:
            q.put_nowait((event, payload))
        except queue.Full:
            pass

    # ---------- subscribers ----------
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

    def pause(self) -> None:
        self._paused = True

    def resume(self) -> None:
        self._paused = False

    def is_paused(self) -> bool:
        return self._paused

    # ---------- SSE generator ----------
    def sse_stream(self):
        q = self.subscribe()
        try:
            yield "event: hello\ndata: {}\n\n"
            while True:
                try:
                    event, payload = q.get(timeout=15)
                except queue.Empty:
                    yield ": keepalive\n\n"
                    continue
                body = json.dumps(payload, default=str)
                yield f"event: {event}\ndata: {body}\n\n"
        finally:
            self.unsubscribe(q)
    
    # ---------------------------
    def publish_intercept(self, payload: dict) -> None:
        with self._lock:
            subs = list(self._subscribers)
        for q in subs:
            self._push(q, "intercept", payload)
    
    


STREAM = PacketStream()