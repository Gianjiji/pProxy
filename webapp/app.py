"""
API FastAPI per pProxy.

Principi privacy-first applicati qui:
* la mappa placeholder→originale resta SOLO lato server, in una sessione effimera
  (vedi `webapp.sessions`), e non viene mai inclusa nelle risposte né nei log;
* l'input è trattato sempre come testo, mai come path di file (vedi `webapp.core`);
* le API key dei provider LLM stanno lato server (variabili d'ambiente) e non
  vengono mai rimandate al client;
* gli errori attesi diventano risposte 4xx pulite, senza traceback.

Avvio:  uvicorn webapp.app:app --reload
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import secrets
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, List, Optional

# Bootstrap del sys.path: assicura che la RADICE del progetto sia importabile, così
# gli import di pacchetto `from webapp.* import …` funzionano anche se l'app viene
# avviata da dentro la cartella `webapp/` (es. `python app.py`) e non solo dalla
# radice (es. `uvicorn webapp.app:app`). Evita il classico
# `ModuleNotFoundError: No module named 'webapp'`.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

_STATIC_DIR = Path(__file__).parent / "static"

from webapp.core import (
    EngineInputError,
    ProviderError,
    anonymize,
    extract_text_from_upload,
    parse_entity_types,
    rehydrate,
    run_pipeline,
)
from webapp.ratelimit import RateLimiter
from webapp.sessions import SessionStore

MAX_TEXT_CHARS = int(os.environ.get("PPROXY_MAX_TEXT_CHARS", "100000"))
MAX_UPLOAD_BYTES = int(os.environ.get("PPROXY_MAX_UPLOAD_BYTES", "5000000"))
# Limite sul corpo della richiesta: difesa in profondità contro l'esaurimento di
# memoria (un body enorme verrebbe letto/parsato prima della validazione Pydantic).
MAX_BODY_BYTES = int(os.environ.get("PPROXY_MAX_BODY_BYTES", "10000000"))
# Autenticazione OPZIONALE, DISABILITATA di default: se PPROXY_API_KEY è impostata,
# gli endpoint dati /api/* (eccetto /api/health) richiedono l'header X-API-Key
# corrispondente. Se non è impostata, il comportamento è invariato (aperto).
API_KEY = os.environ.get("PPROXY_API_KEY", "")
# Allowlist provider LLM (controllo costi), OPZIONALE: se vuota, sono ammessi tutti
# (comportamento invariato). Se valorizzata (CSV), la pipeline accetta solo questi
# provider; gli altri → 403. Es. "demo,ollama" per escludere i provider a pagamento.
ALLOWED_PROVIDERS = {
    p.strip().lower() for p in os.environ.get("PPROXY_ALLOWED_PROVIDERS", "").split(",") if p.strip()
}
SESSION_TTL = int(os.environ.get("PPROXY_SESSION_TTL", "1800"))
RATE_MAX = int(os.environ.get("PPROXY_RATE_MAX", "240"))
RATE_WINDOW = int(os.environ.get("PPROXY_RATE_WINDOW", "60"))
# CORS restrittivo: nessuna origine cross-site consentita finché non se ne
# configurano esplicitamente via env (lista separata da virgole).
CORS_ORIGINS = [o.strip() for o in os.environ.get("PPROXY_CORS_ORIGINS", "").split(",") if o.strip()]
EVICT_INTERVAL = int(os.environ.get("PPROXY_EVICT_INTERVAL", "60"))


async def _eviction_loop() -> None:
    """Purga periodicamente le sessioni scadute: la mappa sensibile non deve
    restare in memoria oltre il TTL anche in assenza di nuove richieste (che
    altrimenti sono l'unico trigger dell'eviction pigra)."""
    while True:
        await asyncio.sleep(EVICT_INTERVAL)
        try:
            store.evict_expired()
        except Exception:  # un errore transitorio non deve fermare il loop
            pass


@asynccontextmanager
async def _lifespan(_app: "FastAPI"):
    task = asyncio.create_task(_eviction_loop())
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title="pProxy Web API",
    description="Anonimizza testi prima di inviarli a un LLM e ripristina i dati originali.",
    version="0.1.0",
    lifespan=_lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)


# Limiter per-IP (sliding window). Per deploy multi-processo sostituire con un
# backend condiviso mantenendo l'interfaccia allow().
rate_limiter = RateLimiter(max_requests=RATE_MAX, window_seconds=RATE_WINDOW)


# NB ordine middleware: queste sono definite PRIMA di _security_headers, quindi
# _security_headers resta la più esterna e applica gli header anche alle risposte
# di errore (401/429/413) prodotte qui. _auth è definita per prima → è la più
# INTERNA delle quattro, così rate-limit e body-limit la precedono (i tentativi
# non autenticati restano comunque limitati per IP).
@app.middleware("http")
async def _auth(request, call_next):
    # I preflight CORS (OPTIONS) NON portano header personalizzati come X-API-Key:
    # vanno lasciati passare al CORSMiddleware, altrimenti l'auth romperebbe i
    # client cross-origin via browser.
    if API_KEY and request.method != "OPTIONS":
        path = request.url.path
        # Protegge solo gli endpoint dati; lascia aperti health, UI e asset statici.
        protected = path.startswith("/api/") and path != "/api/health"
        if protected:
            provided = request.headers.get("x-api-key", "")
            # Confronto a tempo costante per non esporre la chiave via timing.
            if not (provided and secrets.compare_digest(provided, API_KEY)):
                return JSONResponse(
                    status_code=401, content={"detail": "API key mancante o non valida."}
                )
    return await call_next(request)


@app.middleware("http")
async def _limit_body(request, call_next):
    # Rifiuta in anticipo i body troppo grandi via Content-Length, prima che
    # vengano letti/parsati (memoria). Le richieste senza Content-Length (es.
    # chunked) non sono coperte qui: gli endpoint di upload hanno comunque un
    # tetto di lettura dedicato.
    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > MAX_BODY_BYTES:
                return JSONResponse(
                    status_code=413, content={"detail": "Corpo della richiesta troppo grande."}
                )
        except ValueError:
            return JSONResponse(
                status_code=400, content={"detail": "Content-Length non valido."}
            )
    return await call_next(request)


@app.middleware("http")
async def _rate_limit(request, call_next):
    client = request.client.host if request.client else "unknown"
    if not rate_limiter.allow(client):
        return JSONResponse(
            status_code=429,
            content={"detail": "Troppe richieste, riprova più tardi."},
            headers={"Retry-After": str(rate_limiter.retry_after(client))},
        )
    return await call_next(request)


@app.middleware("http")
async def _security_headers(request, call_next):
    """Header di sicurezza + no-store: le risposte contengono testo anonimizzato
    o ripristinato e non devono essere memorizzate in cache da browser/proxy."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    # CSP: l'API non serve risorse (default-src 'none'); la UI statica può caricare
    # solo risorse same-origin (script/style esterni, niente inline).
    if request.url.path.startswith("/api"):
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    else:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
    return response


_access_log = logging.getLogger("pproxy.webapp.access")
# L'ID di sessione nel path è una "capability" (chi lo conosce può ripristinare):
# va redatto dai log di accesso.
_SID_PATH = re.compile(r"^(/api/session/).+$")


def _safe_path(path: str) -> str:
    return _SID_PATH.sub(r"\1<id>", path)


# Definita PER ULTIMA → è la più ESTERNA: assegna l'X-Request-ID a OGNI risposta
# (anche 401/413/429 prodotte dai middleware interni) e registra una riga di
# access log priva di dati sensibili (solo metodo, path sanitizzato, stato, durata).
@app.middleware("http")
async def _request_id_and_access_log(request, call_next):
    rid = request.headers.get("x-request-id") or secrets.token_hex(8)
    start = time.perf_counter()
    response = await call_next(request)
    response.headers["X-Request-ID"] = rid
    _access_log.info(
        "%s %s -> %s (%.1fms) req=%s",
        request.method,
        _safe_path(request.url.path),
        response.status_code,
        (time.perf_counter() - start) * 1000.0,
        rid,
    )
    return response


# Store di sessione condiviso a livello di processo (in-memory, effimero).
store = SessionStore(ttl_seconds=SESSION_TTL)


def _validate_entity_types(types: Optional[List[str]]) -> None:
    """Valida i tipi entità in anticipo per restituire un 400 pulito (il messaggio
    del parser è sicuro: elenca solo i valori ammessi, nessun dato utente)."""
    try:
        parse_entity_types(types)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ── Modelli di richiesta ─────────────────────────────────────

class AnonymizeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=MAX_TEXT_CHARS)
    confidence: float = Field(0.7, ge=0.0, le=1.0)
    use_ner: bool = False
    entity_types: Optional[List[str]] = None
    include_values: bool = False
    # Zero-knowledge: se True il server NON conserva alcuna sessione e restituisce
    # la mappa al client, che la custodisce e la rinvia per il ripristino.
    stateless: bool = False


class RehydrateRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=MAX_TEXT_CHARS)
    # Fornire ESATTAMENTE uno tra: session_id (mappa lato server) oppure mapping
    # (mappa custodita dal client, modalità zero-knowledge).
    session_id: Optional[str] = Field(None, min_length=1, max_length=128)
    mapping: Optional[Dict[str, str]] = Field(None, max_length=20000)


class ProcessRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=MAX_TEXT_CHARS)
    prompt: str = Field("Analizza il seguente testo:\n\n{document}", max_length=8000)
    provider: str = "demo"
    system_prompt: Optional[str] = Field(None, max_length=8000)
    model: Optional[str] = None
    confidence: float = Field(0.7, ge=0.0, le=1.0)
    use_ner: bool = False
    entity_types: Optional[List[str]] = None
    # Dimensione massima dei chunk per documenti lunghi (0 = nessun chunking).
    max_chunk: int = Field(12000, ge=0)
    # Zero-knowledge: non conservare la sessione dopo la pipeline (la risposta
    # finale è già ripristinata; non serve riusare la mappa lato server).
    stateless: bool = False


# ── Endpoint ─────────────────────────────────────────────────

@app.get("/api/health", tags=["stato"], summary="Stato del servizio")
def health() -> dict:
    """Stato del servizio (nessuna informazione sensibile)."""
    return {"status": "ok", "active_sessions": len(store)}


def _check_provider_allowed(provider: str) -> None:
    """Se è configurata un'allowlist, blocca i provider non ammessi (403)."""
    if ALLOWED_PROVIDERS and provider.lower() not in ALLOWED_PROVIDERS:
        raise HTTPException(
            status_code=403,
            detail=f"Provider '{provider}' non consentito su questo server.",
        )


def _anonymize_response(result: dict, stateless: bool) -> dict:
    """Costruisce la risposta di anonimizzazione (sessione vs zero-knowledge)."""
    response = {
        "anonymized_text": result["anonymized_text"],
        "entities": result["entities"],
        "entity_count": len(result["entities"]),
        "validation": result["validation"],
    }
    if stateless:
        # Zero-knowledge: nessuna sessione lato server; la mappa torna al client.
        response["session_id"] = None
        response["mapping"] = result["entity_map"]
    else:
        # Default: la mappa resta lato server, in sessione. NON entra nella risposta.
        response["session_id"] = store.create(result["entity_map"])
    return response


@app.post("/api/anonymize", tags=["anonimizzazione"],
          summary="Anonimizza un testo")
def api_anonymize(req: AnonymizeRequest) -> dict:
    _validate_entity_types(req.entity_types)
    result = anonymize(
        req.text,
        confidence=req.confidence,
        use_ner=req.use_ner,
        entity_types=req.entity_types,
        include_values=req.include_values,
    )
    return _anonymize_response(result, req.stateless)


@app.post("/api/anonymize-file", tags=["anonimizzazione"],
          summary="Anonimizza un file caricato (multipart)")
async def api_anonymize_file(
    file: UploadFile = File(...),
    confidence: float = Form(0.7),
    use_ner: bool = Form(False),
    entity_types: Optional[str] = Form(None),
    include_values: bool = Form(False),
    stateless: bool = Form(False),
) -> dict:
    # Lettura con tetto di dimensione: legge al massimo MAX_UPLOAD_BYTES+1 byte.
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File troppo grande.")
    if not data:
        raise HTTPException(status_code=400, detail="File vuoto.")

    types = [t.strip() for t in entity_types.split(",") if t.strip()] if entity_types else None
    _validate_entity_types(types)
    if not 0.0 <= confidence <= 1.0:
        raise HTTPException(status_code=422, detail="confidence deve essere tra 0 e 1.")

    try:
        text = extract_text_from_upload(file.filename or "upload", data)
    except EngineInputError as exc:
        # Formato non supportato o libreria di parsing assente.
        raise HTTPException(status_code=400, detail=str(exc))

    result = anonymize(
        text,
        confidence=confidence,
        use_ner=use_ner,
        entity_types=types,
        include_values=include_values,
    )
    return _anonymize_response(result, stateless)


@app.post("/api/rehydrate", tags=["ripristino"],
          summary="Ripristina i dati originali (via session_id o mapping)")
def api_rehydrate(req: RehydrateRequest) -> dict:
    # Esattamente uno tra session_id e mapping (controllo esplicito → tipi chiari).
    _both = req.mapping is not None and req.session_id is not None
    if _both or (req.mapping is None and req.session_id is None):
        raise HTTPException(
            status_code=400,
            detail="Fornire esattamente uno tra 'session_id' e 'mapping'.",
        )
    if req.mapping is not None:
        # Modalità zero-knowledge: la mappa è custodita dal client.
        mapping: Dict[str, str] = req.mapping
    else:
        # Qui req.session_id è necessariamente valorizzato (per l'XOR sopra).
        assert req.session_id is not None
        found = store.get_mapping(req.session_id)
        if found is None:
            raise HTTPException(
                status_code=404, detail="Sessione inesistente o scaduta."
            )
        mapping = found
    return rehydrate(req.text, mapping)


def _process_and_respond(text: str, *, prompt_template, provider, system_prompt,
                         model, confidence, use_ner, entity_types, stateless,
                         max_chunk=12000) -> dict:
    """Esegue la pipeline e costruisce la risposta, mappando gli errori su HTTP.
    Condiviso da `/api/process` (testo) e `/api/process-file` (upload)."""
    _check_provider_allowed(provider)
    # max_chunk == 0 → nessun chunking (valore molto grande); evita anche un
    # TextChunker con finestra 0 (che andrebbe in loop).
    max_chunk_chars = max_chunk if max_chunk > 0 else 10 ** 9
    try:
        result = run_pipeline(
            text,
            prompt_template=prompt_template,
            provider=provider,
            system_prompt=system_prompt,
            model=model,
            confidence=confidence,
            use_ner=use_ner,
            entity_types=entity_types,
            max_chunk_chars=max_chunk_chars,
        )
    except RuntimeError as exc:
        # Blocco di sicurezza della validazione anonimizzazione (messaggio nostro, sicuro).
        raise HTTPException(status_code=422, detail=str(exc))
    except ProviderError as exc:
        # Messaggio già sanitizzato in core (nessun dato sensibile).
        raise HTTPException(status_code=502, detail=str(exc))
    except EngineInputError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    session_id = None if stateless else store.create(result["entity_map"])
    return {
        "session_id": session_id,
        "anonymized_text": result["anonymized_text"],
        "final_response": result["final_response"],
        "entities": result["entities"],
        "validation": result["validation"],
    }


@app.post("/api/process", tags=["pipeline"],
          summary="Pipeline completa: anonimizza → LLM → ripristina")
def api_process(req: ProcessRequest) -> dict:
    _validate_entity_types(req.entity_types)
    return _process_and_respond(
        req.text,
        prompt_template=req.prompt,
        provider=req.provider,
        system_prompt=req.system_prompt,
        model=req.model,
        confidence=req.confidence,
        use_ner=req.use_ner,
        entity_types=req.entity_types,
        stateless=req.stateless,
        max_chunk=req.max_chunk,
    )


@app.post("/api/process-file", tags=["pipeline"],
          summary="Pipeline completa su un file caricato (multipart)")
async def api_process_file(
    file: UploadFile = File(...),
    prompt: str = Form("Analizza il seguente testo:\n\n{document}"),
    provider: str = Form("demo"),
    system_prompt: Optional[str] = Form(None),
    model: Optional[str] = Form(None),
    confidence: float = Form(0.7),
    use_ner: bool = Form(False),
    entity_types: Optional[str] = Form(None),
    max_chunk: int = Form(12000),
    stateless: bool = Form(False),
) -> dict:
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File troppo grande.")
    if not data:
        raise HTTPException(status_code=400, detail="File vuoto.")

    types = [t.strip() for t in entity_types.split(",") if t.strip()] if entity_types else None
    _validate_entity_types(types)
    if not 0.0 <= confidence <= 1.0:
        raise HTTPException(status_code=422, detail="confidence deve essere tra 0 e 1.")
    if max_chunk < 0:
        raise HTTPException(status_code=422, detail="max_chunk non può essere negativo.")

    try:
        text = extract_text_from_upload(file.filename or "upload", data)
    except EngineInputError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return _process_and_respond(
        text,
        prompt_template=prompt,
        provider=provider,
        system_prompt=system_prompt,
        model=model,
        confidence=confidence,
        use_ner=use_ner,
        entity_types=types,
        stateless=stateless,
        max_chunk=max_chunk,
    )


@app.get("/api/session/{session_id}", tags=["sessioni"],
         summary="Stato sessione (solo metadati)")
def api_session_status(session_id: str) -> dict:
    """Stato della sessione: metadati soltanto, MAI la mappa o i valori originali."""
    import time as _time

    st = store.status(session_id)
    if st is None:
        raise HTTPException(status_code=404, detail="Sessione inesistente o scaduta.")
    return {
        "active": True,
        "entity_count": int(st["entity_count"]),
        "expires_in": max(0, int(st["expires_at"] - _time.time())),
    }


@app.delete("/api/session/{session_id}", tags=["sessioni"],
            summary="Distrugge una sessione")
def api_delete_session(session_id: str) -> dict:
    existed = store.delete(session_id)
    if not existed:
        raise HTTPException(status_code=404, detail="Sessione inesistente.")
    return {"deleted": True}


# ── UI statica minimale ──────────────────────────────────────

@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(_STATIC_DIR / "index.html")


@app.get("/guida", include_in_schema=False)
def guide() -> FileResponse:
    return FileResponse(_STATIC_DIR / "guide.html")


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> Response:
    # Evita un 404 rumoroso nei log/console del browser (nessuna icona da servire).
    return Response(status_code=204)


app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


if __name__ == "__main__":
    # Permette `python app.py` (anche da dentro webapp/) e `python webapp/app.py`.
    # Per l'auto-reload in sviluppo usare invece: `uvicorn webapp.app:app --reload`
    # oppure `python -m webapp` (vedi webapp/__main__.py).
    import uvicorn

    uvicorn.run(
        app,
        host=os.environ.get("PPROXY_HOST", "127.0.0.1"),
        port=int(os.environ.get("PPROXY_PORT", "8000")),
    )
