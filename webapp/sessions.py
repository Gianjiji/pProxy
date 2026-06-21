"""
Store di sessione per le operazioni di codifica/decodifica.

Una sessione conserva SOLO la mappa `placeholder → dato originale` (il dato più
sensibile del sistema) in memoria, con un TTL. Non viene mai scritta su disco né
serializzata altrove da questo modulo. L'implementazione concreta è in-memory e
thread-safe; `SessionStore` è pensata come punto di estensione (es. backend
cifrato) mantenendo la stessa interfaccia.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class Session:
    id: str
    mapping: Dict[str, str]
    created_at: float
    expires_at: float


class SessionStore:
    """Store in-memory thread-safe con scadenza (TTL) ed eviction pigra + esplicita."""

    def __init__(self, ttl_seconds: int = 1800) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds deve essere positivo")
        self._ttl = ttl_seconds
        self._sessions: Dict[str, Session] = {}
        self._lock = threading.Lock()

    def create(self, mapping: Dict[str, str]) -> str:
        """Crea una sessione con la mappa data e restituisce un ID imprevedibile."""
        self.evict_expired()
        sid = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            self._sessions[sid] = Session(
                id=sid,
                mapping=dict(mapping),
                created_at=now,
                expires_at=now + self._ttl,
            )
        return sid

    def get_mapping(self, session_id: str) -> Optional[Dict[str, str]]:
        """Restituisce una copia della mappa, o None se assente/scaduta (e la rimuove)."""
        with self._lock:
            s = self._sessions.get(session_id)
            if s is None:
                return None
            if s.expires_at < time.time():
                del self._sessions[session_id]
                return None
            return dict(s.mapping)

    def status(self, session_id: str) -> Optional[Dict[str, float]]:
        """Metadati di una sessione (SENZA la mappa): timestamp e numero di voci.
        None se assente/scaduta (e in tal caso la rimuove)."""
        with self._lock:
            s = self._sessions.get(session_id)
            if s is None:
                return None
            if s.expires_at < time.time():
                del self._sessions[session_id]
                return None
            return {
                "created_at": s.created_at,
                "expires_at": s.expires_at,
                "entity_count": float(len(s.mapping)),
            }

    def delete(self, session_id: str) -> bool:
        """Distrugge una sessione. True se esisteva."""
        with self._lock:
            return self._sessions.pop(session_id, None) is not None

    def evict_expired(self) -> int:
        """Rimuove tutte le sessioni scadute. Restituisce il numero rimosso."""
        now = time.time()
        with self._lock:
            expired = [k for k, v in self._sessions.items() if v.expires_at < now]
            for k in expired:
                del self._sessions[k]
        return len(expired)

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)
