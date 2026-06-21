"""
Rate limiter in-memory (sliding window), senza dipendenze esterne.

Pensato per un singolo processo: tiene per ogni chiave (es. IP client) i timestamp
delle richieste nella finestra corrente. Per deploy multi-processo/multi-istanza
andrebbe sostituito con un backend condiviso (es. Redis), mantenendo la stessa
interfaccia `allow(key)`.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict


class RateLimiter:
    def __init__(self, max_requests: int = 240, window_seconds: int = 60) -> None:
        if max_requests <= 0 or window_seconds <= 0:
            raise ValueError("max_requests e window_seconds devono essere positivi")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        """Registra una richiesta per `key`. False se la finestra è satura."""
        now = time.time()
        cutoff = now - self.window_seconds
        with self._lock:
            q = self._hits[key]
            while q and q[0] < cutoff:
                q.popleft()
            if len(q) >= self.max_requests:
                return False
            q.append(now)
            return True

    def retry_after(self, key: str) -> int:
        """Secondi (>=1) prima che `key` torni ammissibile, se la finestra è piena;
        0 se c'è ancora spazio. Usato per l'header HTTP Retry-After sui 429."""
        now = time.time()
        with self._lock:
            q = self._hits[key]
            while q and q[0] < now - self.window_seconds:
                q.popleft()
            if len(q) < self.max_requests:
                return 0
            # Il posto più vecchio si libera a q[0] + window_seconds.
            return max(1, int(q[0] + self.window_seconds - now) + 1)

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()
