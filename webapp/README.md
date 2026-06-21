# pProxy Web App

Interfaccia HTTP + UI minimale attorno al motore `pProxy`. Anonimizza un testo (o
un file), opzionalmente lo invia a un LLM e ripristina i dati originali.

## Principio privacy-first

La mappa `placeholder → dato originale` è il dato più sensibile del sistema:

- non viene mai inviata all'LLM, scritta su disco in chiaro, o registrata nei log;
- in modalità **default** resta lato server in una **sessione effimera** (TTL,
  purgata anche in background) e non compare nelle risposte;
- in modalità **zero-knowledge** (`stateless: true`) il server **non conserva
  nulla**: la mappa torna al client, che la custodisce e la rinvia per il ripristino.

## Avvio

### Locale

Installa le **dipendenze** (non esiste un pacchetto `webapp` su PyPI: `pip install webapp`
darebbe errore — è codice locale):

```bash
pip install -r requirements.txt -r requirements-web.txt
```

Poi avvia il server **dalla radice del progetto** (la cartella che contiene `webapp/`),
con uno qualsiasi di questi comandi equivalenti:

```bash
uvicorn webapp.app:app --reload     # consigliato in sviluppo (auto-reload)
python -m webapp                    # equivalente; PPROXY_RELOAD=1 per il reload
python webapp/app.py                # avvio diretto
```

> Anche `python app.py` da **dentro** la cartella `webapp/` ora funziona (il path
> della radice viene aggiunto automaticamente). In sviluppo resta però preferibile
> `uvicorn … --reload` / `python -m webapp` per l'auto-reload.

Apri http://localhost:8000/ (UI a schede: Anonimizza · Ripristina · Pipeline · Sessioni),
http://localhost:8000/guida (guida all'uso) o http://localhost:8000/docs (OpenAPI).
Host/porta configurabili con `PPROXY_HOST` / `PPROXY_PORT`.

> Per upload di PDF/CSV/DOCX servono le relative dipendenze opzionali del core
> (`pdfplumber`/`pymupdf`, `pandas`, `python-docx`). TXT e JSON funzionano senza extra.

### Docker

```bash
docker build -t pproxy-web .
docker run --rm -p 8000:8000 pproxy-web
```

## Endpoint

| Metodo | Path | Descrizione |
|--------|------|-------------|
| GET  | `/api/health` | Stato del servizio |
| POST | `/api/anonymize` | Anonimizza un testo |
| POST | `/api/anonymize-file` | Anonimizza un file caricato (multipart) |
| POST | `/api/rehydrate` | Ripristina i dati (via `session_id` o `mapping`) |
| POST | `/api/process` | Pipeline completa: anonimizza → LLM → ripristina |
| POST | `/api/process-file` | Pipeline completa su un file caricato (multipart) |
| GET | `/api/session/{id}` | Stato sessione (solo metadati: conteggio entità, TTL residuo) |
| DELETE | `/api/session/{id}` | Distrugge una sessione |

### Esempi

Anonimizzazione (sessione lato server):

```bash
curl -s localhost:8000/api/anonymize \
  -H 'Content-Type: application/json' \
  -d '{"text": "Scrivi a mario.rossi@example.com", "use_ner": false}'
# → { "session_id": "...", "anonymized_text": "Scrivi a [EMAIL_001]", ... }
```

Ripristino con la sessione:

```bash
curl -s localhost:8000/api/rehydrate \
  -H 'Content-Type: application/json' \
  -d '{"text": "[EMAIL_001]", "session_id": "<id>"}'
```

Zero-knowledge (la mappa torna al client, niente sessione):

```bash
curl -s localhost:8000/api/anonymize \
  -H 'Content-Type: application/json' \
  -d '{"text": "...", "stateless": true}'
# → { "session_id": null, "mapping": { "[EMAIL_001]": "..." }, ... }
# poi /api/rehydrate con {"text": "...", "mapping": { ... }}
```

Upload file:

```bash
curl -s -F 'file=@documento.txt' -F 'use_ner=false' localhost:8000/api/anonymize-file
```

## Configurazione (variabili d'ambiente)

| Variabile | Default | Significato |
|-----------|---------|-------------|
| `PPROXY_SESSION_TTL` | `1800` | TTL sessioni (secondi) |
| `PPROXY_EVICT_INTERVAL` | `60` | Intervallo del purga-sessioni in background (s) |
| `PPROXY_RATE_MAX` | `240` | Richieste max per finestra (per IP) |
| `PPROXY_RATE_WINDOW` | `60` | Ampiezza finestra rate limit (s) |
| `PPROXY_MAX_TEXT_CHARS` | `100000` | Lunghezza massima del testo |
| `PPROXY_MAX_UPLOAD_BYTES` | `5000000` | Dimensione massima upload |
| `PPROXY_MAX_BODY_BYTES` | `10000000` | Dimensione massima del corpo richiesta (413 oltre) |
| `PPROXY_CORS_ORIGINS` | *(vuoto)* | Origini CORS consentite (CSV) |
| `PPROXY_API_KEY` | *(vuoto)* | Se impostata, gli endpoint `/api/*` (tranne `/api/health`) richiedono l'header `X-API-Key` corrispondente |
| `PPROXY_ALLOWED_PROVIDERS` | *(vuoto = tutti)* | Allowlist provider per la pipeline (CSV, es. `demo,ollama`); gli altri → `403` |

Le API key dei provider LLM si impostano lato server come variabili d'ambiente
(`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`) e non sono mai esposte al client.

## Note di produzione

L'app applica già: rate limiting per IP, limiti su testo/upload/corpo richiesta
(`Content-Length`), header di sicurezza, CORS restrittivo, sessioni effimere ed errori
sanitizzati. Ogni risposta ha un header **`X-Request-ID`** (generato o propagato dal
client) e viene emessa una riga di **access log** (`pproxy.webapp.access`) priva di dati
sensibili — il path delle sessioni è redatto (`/api/session/<id>`). Per un'esposizione su
Internet si raccomanda comunque:

- **Reverse proxy** (nginx/Caddy/Traefik) davanti all'app per: **TLS/HTTPS**, e un limite
  di body *hard* a livello di proxy (es. `client_max_body_size` in nginx) che copre anche
  le richieste *chunked* prive di `Content-Length` (non gestibili dal solo controllo
  applicativo).
- **Autenticazione/autorizzazione** se l'app non deve essere pubblica: senza, chiunque può
  consumare la quota API del provider configurato lato server. È disponibile un'auth via
  API key **opzionale e disattivata di default**: impostando `PPROXY_API_KEY`, gli endpoint
  dati richiedono l'header `X-API-Key`. `/api/health` e la UI restano aperti; se abiliti
  l'auth, la UI inclusa va usata dietro un proxy che inietta la chiave, oppure tramite
  chiamate API dirette. Per esigenze più ricche (OAuth, per-utente) usa un gateway dedicato.
- **Più worker**: `RateLimiter` e lo store di sessione sono per-processo (in-memory). Per
  deploy multi-worker/multi-istanza usare un backend condiviso (es. Redis) mantenendo le
  interfacce `allow()` / `SessionStore`.
