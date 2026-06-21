"""
Avvio della web app come modulo:  python -m webapp   (dalla radice del progetto).

Usa la stringa di import "webapp.app:app" così da supportare l'auto-reload.
Variabili d'ambiente: PPROXY_HOST (default 127.0.0.1), PPROXY_PORT (8000),
PPROXY_RELOAD (qualsiasi valore non vuoto abilita il reload in sviluppo).
"""

from __future__ import annotations

import os


def main() -> None:
    import uvicorn

    uvicorn.run(
        "webapp.app:app",
        host=os.environ.get("PPROXY_HOST", "127.0.0.1"),
        port=int(os.environ.get("PPROXY_PORT", "8000")),
        reload=bool(os.environ.get("PPROXY_RELOAD")),
    )


if __name__ == "__main__":
    main()
