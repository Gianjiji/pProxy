# Inventario di copertura — funzionalità pProxy → API → UI

Stato della Fase 0 (studio). Obiettivo: copertura **100%** — ogni funzionalità di
`pProxy.py` raggiungibile e configurabile dalla UI. Legenda: ✅ coperto · 🟡 parziale ·
❌ da fare.

## Modalità / comandi

| Funzionalità (flag CLI) | Endpoint API | Controllo UI | Stato |
|---|---|---|---|
| Anonimizza testo (`--anonymize-only` + `--text`) | `POST /api/anonymize` | scheda Anonimizza | ✅ |
| Anonimizza file (`--file`) | `POST /api/anonymize-file` | scheda Anonimizza (file) | ✅ |
| Ripristina da sessione (`--rehydrate-from`) | `POST /api/rehydrate` (session_id) | scheda Ripristina | ✅ |
| Ripristina con mappa client (zero-knowledge) | `POST /api/rehydrate` (mapping) | scheda Ripristina (zk) | ✅ |
| Pipeline LLM testo | `POST /api/process` | scheda Pipeline | ✅ |
| Pipeline LLM file | `POST /api/process-file` | scheda Pipeline (file) | ✅ |
| Stato sessione | `GET /api/session/{id}` | scheda Sessioni | ✅ |
| Elimina sessione | `DELETE /api/session/{id}` | scheda Sessioni | ✅ |
| **Dry-run / solo rilevamento** (`--dry-run`) | ❌ | ❌ | ❌ |
| **Highlight inline** (`--highlight`) `{val\|TIPO:conf}` | ❌ | ❌ | ❌ |
| **Redact** (`--redact`) → `[REDACTED]` irreversibile | ❌ | ❌ | ❌ |
| **Batch / cartella** (`--dir`) | ❌ (valutare multi-upload) | ❌ | ❌ |

## Opzioni di rilevamento/anonimizzazione

| Opzione (flag) | API | UI | Stato |
|---|---|---|---|
| Soglia confidenza (`--confidence`) | body | opzioni | ✅ |
| Disabilita NER (`--no-ner`) | body `use_ner` | opzioni | ✅ |
| Filtro tipi entità (`--entity-types`, 14 tipi + forme estese) | body | opzioni | ✅ |
| Mostra valori rilevati (`include_values`) | anonymize body | opzioni | ✅ |
| Zero-knowledge (`stateless`) | body | opzioni | ✅ |
| Max chunk (`--max-chunk`) | process body | opzioni pipeline | ✅ |

## Pipeline LLM

| Parametro (flag) | API | UI | Stato |
|---|---|---|---|
| Provider (`--provider`) | process body | select | ✅ |
| Modello (`--model`) | process body | campo | ✅ |
| Prompt `{document}` (`--prompt`) | process body | campo | ✅ |
| System prompt (`--system-prompt`) | process body | campo | ✅ |
| **Ollama base URL** (`--ollama-url`) | 🟡 gateway lo supporta, l'endpoint NO | ❌ | ❌ |
| **Non fermarti su errore** (`--no-stop-on-error`) | 🟡 `run_pipeline` ha il flag, l'endpoint lo fissa a True | ❌ | ❌ |

## Reportistica

| Funzionalità (flag) | API | UI | Stato |
|---|---|---|---|
| Statistiche dettagliate (`--stats`) | 🟡 entità in risposta, niente aggregati | ❌ vista | 🟡 |
| Sorgenti rilevamento (`--show-sources`) | 🟡 `source` per entità | ❌ vista | 🟡 |
| Mostra mappa (`--show-map`) | 🟡 solo in zero-knowledge | scheda Anonimizza (zk) | 🟡 |

## Persistenza mappa cifrata

| Funzionalità (flag) | API | UI | Stato |
|---|---|---|---|
| **Salva mappa cifrata** (`--save-mapping` + `--encryption-key`, AES) | ❌ | ❌ | ❌ |
| **Carica mappa cifrata per ripristino** (`--load-mapping`) | ❌ | ❌ | ❌ |

## Output / varie

| Funzionalità (flag) | API | UI | Stato |
|---|---|---|---|
| Salva risultato su file (`--output`) | N/A web | 🟡 copia; manca **download** | 🟡 |
| Verbose (`--verbose`) | logging server | N/A | N/A |
| API key provider LLM (`--api-key`) | env lato server | N/A (chiave server) | N/A |
| API key dell'app (auth) | header `X-API-Key` | campo API key | ✅ |

## Gap prioritari da chiudere (per il loop)

1. **`POST /api/detect`** — dry-run: rilevamento con **statistiche** aggregate e **sorgenti**, testo invariato → schede "Rilevamento" (stats/sorgenti) e show-map.
2. **`POST /api/highlight`** — testo con entità marcate inline.
3. **`POST /api/redact`** — testo con `[REDACTED]` (irreversibile, nessuna sessione).
4. **Mappa cifrata**: download della mappa cifrata (AES, passphrase) dopo l'anonimizzazione e upload per il ripristino → riusa `SecureMappingStore`.
5. **Parametri pipeline mancanti**: `ollama_base_url`, `stop_on_error` (toggle).
6. **Viste reportistica** in UI: statistiche, sorgenti, validazione dettagliata.
7. **Pulsanti download** per gli output (anonimizzato, ripristinato, redatto, mappa).
8. (Opzionale) **multi-file** come equivalente web del batch `--dir`.

Aggiornare questo file man mano che i gap vengono chiusi.
