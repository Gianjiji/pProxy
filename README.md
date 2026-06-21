# pProxy — Privacy Proxy per LLM

Anonimizza documenti contenenti dati sensibili prima di inviarli a un LLM cloud, poi ripristina automaticamente i valori originali nella risposta.

I dati sensibili vengono sostituiti con placeholder deterministici (`[EMAIL_001]`, `[PERSON_002]`…) che l'LLM riceve al posto dei dati reali. La mappa di ripristino non lascia mai la macchina locale.

Disponibile sia come **CLI/libreria** (`pProxy.py`) sia come **web app** con interfaccia a schede e guida integrata (vedi [Web app](#web-app)).

---

## Indice

- [Requisiti e installazione](#requisiti-e-installazione)
- [Dati rilevati](#dati-rilevati)
- [Pipeline completa con LLM](#pipeline-completa-con-llm)
- [Solo anonimizzazione](#solo-anonimizzazione)
- [Flusso manuale: anonimizza → AI esterna → ripristina](#flusso-manuale)
- [Dry-run: anteprima senza modifiche](#dry-run)
- [Highlight: testo con entità evidenziate](#highlight)
- [Redazione permanente](#redazione-permanente)
- [Elaborazione batch di una cartella](#elaborazione-batch)
- [Cifratura della mappa](#cifratura-della-mappa)
- [Filtrare i tipi di entità](#filtrare-i-tipi-di-entità)
- [Opzioni avanzate](#opzioni-avanzate)
- [Riferimento completo argomenti CLI](#riferimento-completo)
- [Web app](#web-app)

---

## Requisiti e installazione

**Python 3.9+** richiesto.

### Dipendenze base

Il **core non ha dipendenze esterne obbligatorie**: anonimizzazione regex, mappa in chiaro, ripristino e provider `demo` funzionano con la sola libreria standard di Python. Tutte le dipendenze elencate di seguito sono opzionali — lo script degrada in modo *graceful* e avvisa quando una funzionalità richiede un pacchetto non installato.

`requirements.txt` installa solo gli strumenti di test (`pytest`) e tiene le dipendenze opzionali commentate, pronte da abilitare:

```bash
pip install -r requirements.txt
```

### Dipendenze opzionali per formati di file

```bash
pip install pdfplumber          # PDF testuali
pip install pymupdf             # PDF testuali (alternativa)
pip install pytesseract pdf2image  # PDF scansionati (OCR)
pip install pandas              # CSV con inferenza colonne
pip install python-docx         # File DOCX
```

### Dipendenze opzionali per NER avanzato

Tutti i motori NER sono facoltativi: lo script funziona anche con solo regex.

```bash
pip install spacy
python -m spacy download it_core_news_sm   # modello italiano

pip install gliner               # NER zero-shot multilingue
pip install presidio-analyzer    # Microsoft Presidio
```

### Dipendenze opzionali per provider LLM

```bash
pip install openai               # OpenAI
pip install anthropic            # Anthropic / Claude
pip install google-generativeai  # Google Gemini
pip install requests             # Ollama (locale)
```

### Cifratura mappa (opzionale)

```bash
pip install cryptography         # AES-256 per la mappa entità
```

---

## Dati rilevati

| Tipo | Descrizione | Validazione |
|------|-------------|-------------|
| `PERSON` | Nomi propri preceduti da titolo (Dott., Sig., Prof., Avv.…) | NER + regex |
| `EMAIL` | Indirizzi email | Regex |
| `PHONE` | Numeri italiani (+39, cellulari) e internazionali | Regex |
| `IBAN` | Codici IBAN | Algoritmo modulo 97 (ISO 13616) |
| `CF` | Codice Fiscale italiano | Verifica carattere di controllo |
| `PIVA` | Partita IVA italiana | Verifica checksum 11 cifre |
| `CARD` | Numeri carta di credito | Algoritmo di Luhn |
| `ADDRESS` | Indirizzi italiani (Via, Corso, Piazza…) | Regex |
| `DATE` | Date numeriche e in italiano scritto | Regex |
| `AMOUNT` | Importi monetari (€, $, £) e con etichette testuali | Regex |
| `CAP` | Codici di avviamento postale | Regex |
| `ACCOUNT` | Numeri di conto corrente | Regex |
| `LOC` | Luoghi e città | NER |
| `ORG` | Organizzazioni e aziende | NER |

---

## Pipeline completa con LLM

Anonimizza il documento, lo invia all'LLM e ripristina i dati originali nella risposta.

### Anthropic (Claude)

```bash
export ANTHROPIC_API_KEY="sk-ant-..."

python pProxy.py \
  --file contratto.pdf \
  --provider anthropic \
  --prompt "Riassumi il seguente documento in 5 punti:\n\n{document}"
```

### OpenAI (GPT)

```bash
export OPENAI_API_KEY="sk-..."

python pProxy.py \
  --file verbale.docx \
  --provider openai \
  --model gpt-4o \
  --prompt "Estrai le clausole principali dal seguente testo:\n\n{document}"
```

### Google Gemini

```bash
export GOOGLE_API_KEY="..."

python pProxy.py \
  --file report.txt \
  --provider gemini
```

### Ollama (locale, nessuna API key)

```bash
python pProxy.py \
  --file documento.txt \
  --provider ollama \
  --model llama3.2 \
  --ollama-url http://localhost:11434
```

### Provider Demo (nessuna API key, per test)

```bash
python pProxy.py \
  --file documento.txt \
  --provider demo
```

### Testo libero invece di un file

```bash
python pProxy.py \
  --text "Mario Rossi, CF: RSSMRA80A01H501Z, tel 333-1234567, mario@example.com" \
  --provider anthropic \
  --prompt "Analizza questo testo:\n\n{document}"
```

### Salvataggio del risultato in JSON

```bash
python pProxy.py \
  --file contratto.pdf \
  --provider anthropic \
  --output risultato.json
```

---

## Solo anonimizzazione

Anonimizza il documento senza inviarlo a nessun LLM.

```bash
python pProxy.py \
  --file documento.pdf \
  --anonymize-only
```

Output di esempio:

```
────────────────────────────────────────────────────────────
 TESTO ANONIMIZZATO
────────────────────────────────────────────────────────────
Gentile [PERSON_001], la informiamo che il saldo del conto
intestato a [PERSON_001] (CF [CF_001]) è di [AMOUNT_001].
Per informazioni contattare [EMAIL_001] oppure [PHONE_001].

────────────────────────────────────────────────────────────
 ENTITÀ RILEVATE  (5)
────────────────────────────────────────────────────────────
  [PERSON  ] conf=0.88  Mario Rossi
  [CF      ] conf=0.99  RSSMRA80A01H501Z
  [AMOUNT  ] conf=0.95  € 12.500,00
  [EMAIL   ] conf=0.99  mario.rossi@example.com
  [PHONE   ] conf=0.92  +39 333 1234567
```

### Con mappa placeholder → originale

```bash
python pProxy.py \
  --file documento.pdf \
  --anonymize-only \
  --show-map
```

### Con statistiche dettagliate

```bash
python pProxy.py \
  --file documento.pdf \
  --anonymize-only \
  --stats
```

---

## Flusso manuale

Utile quando si vuole scegliere autonomamente quale AI usare (interfaccia web, API proprietarie, ecc.) senza configurare il gateway.

### Passo 1 — Anonimizza e salva la mappa

```bash
python pProxy.py \
  --file documento.pdf \
  --anonymize-only \
  --save-mapping mappa.json \
  --output risultato.json
```

Estrai il testo anonimizzato dal JSON di output:

```bash
python -c "import json; print(json.load(open('risultato.json'))['anonymized_text'])"
```

Oppure lascia che lo script lo stampi a schermo (senza `--output`) e copialo manualmente.

### Passo 2 — Usa l'AI che preferisci

Incolla il testo anonimizzato nel tuo LLM (ChatGPT, Claude.ai, Gemini, ecc.) con il prompt desiderato. L'AI vedrà solo i placeholder e risponderà usando quelli.

Salva la risposta dell'AI in un file:

```
risposta_ai.txt
```

### Passo 3 — Ripristina i dati originali

```bash
python pProxy.py \
  --rehydrate-from risposta_ai.txt \
  --load-mapping mappa.json
```

I placeholder vengono sostituiti con i valori originali e il risultato viene stampato a schermo.

### Salva anche il testo ripristinato su file

```bash
python pProxy.py \
  --rehydrate-from risposta_ai.txt \
  --load-mapping mappa.json \
  --output testo_finale.txt
```

---

## Dry-run

Mostra quali entità verrebbero anonimizzate **senza modificare nulla**. Utile per calibrare la soglia di confidenza prima di elaborare un documento reale.

```bash
python pProxy.py \
  --file documento.pdf \
  --dry-run
```

Output di esempio:

```
────────────────────────────────────────────────────────────
 DRY-RUN – ENTITÀ CHE VERREBBERO ANONIMIZZATE  (4)
────────────────────────────────────────────────────────────
  [EMAIL   ] conf=0.99  pos=42-67   'mario.rossi@example.com'
  [PHONE   ] conf=0.92  pos=80-95   '+39 333 1234567'
  [CF      ] conf=0.99  pos=120-136 'RSSMRA80A01H501Z'
  [PERSON  ] conf=0.88  pos=0-10    'Mario Rossi'

  Riepilogo: CF=1  EMAIL=1  PERSON=1  PHONE=1
```

### Dry-run con sorgente del rilevatore

```bash
python pProxy.py \
  --file documento.pdf \
  --dry-run \
  --show-sources
```

### Dry-run con soglia di confidenza personalizzata

```bash
python pProxy.py \
  --file documento.pdf \
  --dry-run \
  --confidence 0.85
```

### Salva le entità rilevate in JSON

```bash
python pProxy.py \
  --file documento.pdf \
  --dry-run \
  --output entita.json
```

---

## Highlight

Stampa il testo originale con le entità marcate inline nel formato `{valore|TIPO:confidenza}`. Utile per revisione visiva prima di procedere con l'anonimizzazione.

```bash
python pProxy.py \
  --file documento.pdf \
  --highlight
```

Output di esempio:

```
Gentile {Mario Rossi|PERSON:0.88}, la sua email {mario@example.com|EMAIL:0.99}
è stata registrata. Il CF {RSSMRA80A01H501Z|CF:0.99} risulta valido.
```

### Salva il testo evidenziato

```bash
python pProxy.py \
  --file documento.pdf \
  --highlight \
  --output testo_evidenziato.txt
```

---

## Redazione permanente

Sostituisce i dati sensibili con `[REDACTED]` in modo **irreversibile**. Nessuna mappa viene conservata: i dati originali non sono recuperabili.

```bash
python pProxy.py \
  --file documento.pdf \
  --redact
```

Output di esempio:

```
────────────────────────────────────────────────────────────
 TESTO REDATTO
────────────────────────────────────────────────────────────
Gentile [REDACTED], il suo CF [REDACTED] e la sua email
[REDACTED] sono stati rimossi dal documento.

────────────────────────────────────────────────────────────
 ENTITÀ REDATTE  (3)
────────────────────────────────────────────────────────────
  CF=1  EMAIL=1  PERSON=1
```

### Salva il documento redatto

```bash
python pProxy.py \
  --file documento.pdf \
  --redact \
  --output documento_redatto.txt
```

---

## Elaborazione batch

Elabora tutti i file supportati (PDF, CSV, TXT, DOCX, JSON) in una cartella.

```bash
python pProxy.py \
  --dir ./documenti/ \
  --anonymize-only
```

### Salva i file anonimizzati in una cartella di output

```bash
python pProxy.py \
  --dir ./documenti/ \
  --anonymize-only \
  --output ./documenti_anonimizzati/
```

Per ogni file `nome.pdf` viene creato `nome_anon.txt` nella cartella di output.

### Batch con invio all'LLM

```bash
python pProxy.py \
  --dir ./documenti/ \
  --provider anthropic \
  --prompt "Riassumi:\n\n{document}"
```

---

## Cifratura della mappa

La mappa `placeholder → originale` può essere cifrata con **AES-256** tramite una passphrase. Il file risultante è illeggibile senza la chiave.

### Anonimizza con mappa cifrata

```bash
python pProxy.py \
  --file documento.pdf \
  --anonymize-only \
  --save-mapping mappa.enc \
  --encryption-key "la-mia-passphrase-segreta"
```

### Ripristina usando la mappa cifrata

```bash
python pProxy.py \
  --rehydrate-from risposta_ai.txt \
  --load-mapping mappa.enc \
  --encryption-key "la-mia-passphrase-segreta"
```

### Pipeline completa con cifratura

```bash
python pProxy.py \
  --file documento.pdf \
  --provider anthropic \
  --save-mapping mappa.enc \
  --encryption-key "la-mia-passphrase-segreta" \
  --output risultato.json
```

> Richiede: `pip install cryptography`

---

## Filtrare i tipi di entità

Per rilevare e anonimizzare solo determinati tipi di dati sensibili, usa `--entity-types` con una lista separata da virgole.

Valori disponibili: `PERSON`, `ORG`, `LOC`, `ADDR`, `EMAIL`, `PHONE`, `IBAN`, `CF`, `PIVA`, `CARD`, `DATE`, `AMOUNT`, `CAP`, `ACCOUNT`

> Per `ORG`, `LOC` e `ADDR` sono accettate anche le forme estese `ORGANIZATION`, `LOCATION` e `ADDRESS`. Il confronto è case-insensitive.

### Solo email e numeri di telefono

```bash
python pProxy.py \
  --file documento.pdf \
  --anonymize-only \
  --entity-types EMAIL,PHONE
```

### Solo dati finanziari

```bash
python pProxy.py \
  --file estratto_conto.pdf \
  --anonymize-only \
  --entity-types IBAN,AMOUNT,ACCOUNT,CARD
```

### Solo dati anagrafici italiani

```bash
python pProxy.py \
  --file anagrafica.csv \
  --anonymize-only \
  --entity-types PERSON,CF,PIVA,DATE,EMAIL,PHONE,ADDRESS
```

---

## Opzioni avanzate

### Disabilitare il NER (solo regex, più veloce)

```bash
python pProxy.py \
  --file documento.pdf \
  --anonymize-only \
  --no-ner
```

Utile quando le dipendenze NER non sono installate o quando la velocità è prioritaria.

### Soglia di confidenza personalizzata

```bash
python pProxy.py \
  --file documento.pdf \
  --anonymize-only \
  --confidence 0.85
```

Valore tra `0.0` e `1.0`. Default: `0.7`. Più alto = meno falsi positivi, ma possibili mancati rilevamenti.

### Documenti lunghi: dimensione chunk

```bash
python pProxy.py \
  --file documento_lungo.pdf \
  --provider anthropic \
  --max-chunk 8000
```

Default: 12.000 caratteri per chunk. Usa `--max-chunk 0` per disabilitare il chunking.

### Disabilitare il blocco su errori di validazione

```bash
python pProxy.py \
  --file documento.pdf \
  --provider anthropic \
  --no-stop-on-error
```

> **Sconsigliato**: per default lo script si blocca se rileva che un dato originale potrebbe essere trapelato nel testo anonimizzato prima dell'invio all'LLM.

### System prompt per l'LLM

```bash
python pProxy.py \
  --file documento.pdf \
  --provider anthropic \
  --system-prompt "Sei un assistente legale specializzato in contratti italiani." \
  --prompt "Analizza questo contratto:\n\n{document}"
```

### Output verboso (log dettagliato)

```bash
python pProxy.py \
  --file documento.pdf \
  --anonymize-only \
  --verbose
```

---

## Riferimento completo

```
python pProxy.py [OPZIONI]

INPUT (uno dei seguenti, obbligatorio):
  --file, -f PATH          File da elaborare (PDF, CSV, TXT, DOCX, JSON)
  --text, -t TESTO         Testo libero da anonimizzare
  --dir, -d CARTELLA       Elabora tutti i file supportati in una cartella

LLM:
  --provider, -p           openai | anthropic | gemini | ollama | demo
                           (default: anthropic)
  --api-key, -k KEY        API key del provider
  --model, -m MODELLO      Modello da usare (default dipende dal provider)
  --ollama-url URL         URL Ollama (default: http://localhost:11434)
  --prompt TEMPLATE        Template prompt con {document} come segnaposto
  --system-prompt TESTO    System prompt opzionale

RILEVAMENTO:
  --confidence 0-1         Soglia di confidenza (default: 0.7)
  --entity-types TIPI      Filtra i tipi (es: EMAIL,PHONE,IBAN)
  --no-ner                 Solo regex, disabilita NER
  --max-chunk CHARS        Dimensione chunk per documenti lunghi (default: 12000)

MODALITÀ:
  --anonymize-only         Solo anonimizzazione, senza LLM
  --dry-run                Anteprima entità senza modificare il testo
  --highlight              Testo con entità marcate inline
  --redact                 Redazione permanente con [REDACTED]
  --rehydrate-from FILE    Ripristina placeholder da file o testo

SICUREZZA:
  --save-mapping FILE      Salva la mappa entità
  --load-mapping FILE      Carica una mappa salvata
  --encryption-key PASS    Cifra/decifra la mappa con AES-256
  --no-stop-on-error       Non bloccare su errori di validazione (sconsigliato)

OUTPUT:
  --output, -o FILE        Salva il risultato in JSON (o cartella per --dir)
  --show-map               Mostra la mappa placeholder → originale
  --show-sources           Mostra quale rilevatore ha trovato ogni entità
  --stats                  Statistiche dettagliate per tipo e confidenza
  --verbose, -v            Log dettagliato
```

### Modelli default per provider

| Provider | Modello default |
|----------|----------------|
| `anthropic` | `claude-haiku-4-5-20251001` |
| `openai` | `gpt-4o-mini` |
| `gemini` | `gemini-1.5-flash` |
| `ollama` | `llama3.2` |

### Variabili d'ambiente per le API key

| Provider | Variabile |
|----------|-----------|
| `anthropic` | `ANTHROPIC_API_KEY` |
| `openai` | `OPENAI_API_KEY` |
| `gemini` | `GOOGLE_API_KEY` |

---

## Web app

Oltre alla CLI, pProxy include una **web app** (FastAPI + interfaccia a schede) che
espone le funzionalità via HTTP e tramite UI, con **sessioni effimere** e una modalità
**zero-knowledge** in cui il server non conserva mai la mappa dei dati reali.

### Avvio

```bash
pip install -r requirements.txt -r requirements-web.txt
uvicorn webapp.app:app --reload      # oppure: python -m webapp
```

Poi apri:
- **http://localhost:8000/** — interfaccia (schede: *Anonimizza · Ripristina · Pipeline LLM · Sessioni*)
- **http://localhost:8000/guida** — guida all'uso integrata
- **http://localhost:8000/docs** — documentazione API (OpenAPI/Swagger)

In alternativa con Docker: `docker build -t pproxy-web . && docker run --rm -p 8000:8000 pproxy-web`.

### Interfaccia

L'UI copre i flussi principali:
- **Anonimizza** — testo o file (TXT/JSON/CSV/PDF/DOCX) → testo con placeholder + ID sessione.
- **Ripristina** — incolli la risposta della tua AI (con i placeholder) e ottieni i dati reali.
- **Pipeline LLM** — pProxy anonimizza, chiama l'AI (provider `demo`/openai/anthropic/gemini/ollama) e restituisce la risposta già ripristinata.
- **Sessioni** — verifica/elimina le sessioni lato server.

Opzioni configurabili da UI: soglia di confidenza, filtro tipi entità, NER, mostra valori,
max-chunk, modalità zero-knowledge, provider/modello/prompt, e campo API key.

### Endpoint API

| Metodo | Path | Descrizione |
|--------|------|-------------|
| `POST` | `/api/anonymize` · `/api/anonymize-file` | Anonimizza testo / file |
| `POST` | `/api/rehydrate` | Ripristina (via `session_id` o `mapping`) |
| `POST` | `/api/process` · `/api/process-file` | Pipeline completa anonimizza→LLM→ripristina |
| `GET`/`DELETE` | `/api/session/{id}` | Stato / eliminazione sessione |
| `GET` | `/api/health` | Stato del servizio |

### Sicurezza & privacy

La mappa placeholder→valore non viene **mai** inviata all'LLM, scritta in chiaro o
registrata nei log. La web app applica inoltre: rate limiting per IP, limiti su
testo/upload/corpo richiesta, header di sicurezza + CSP, CORS restrittivo, errori
sanitizzati, e — opzionali, disattivate di default — **autenticazione via API key**
(`PPROXY_API_KEY`) e **allowlist provider** (`PPROXY_ALLOWED_PROVIDERS`).

Dettagli completi, esempi di chiamata, configurazione (variabili d'ambiente) e note di
produzione: vedi **[`webapp/README.md`](webapp/README.md)**. La copertura
funzionalità→endpoint→UI è tracciata in [`webapp/COVERAGE.md`](webapp/COVERAGE.md).

---

## Licenza

Distribuito sotto licenza **MIT**.

```
MIT License

Copyright (c) 2025 Gianluigi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Architettura

```
Documento
    │
    ▼
[Modulo 1] Input Layer          PDF / CSV / TXT / DOCX / JSON → testo uniforme
    │
    ▼
[Modulo 2] Detection Engine     Regex + spaCy + GLiNER + Presidio → entità rilevate
    │
    ▼
[Modulo 3] Tokenization Engine  Sostituzione deterministica → testo anonimizzato
    │
    ▼
[Modulo 4] Secure Mapping Store Mappa locale (AES-256 opzionale) — mai inviata all'LLM
    │
    ▼
[Modulo 5] LLM Gateway          OpenAI / Anthropic / Gemini / Ollama / Demo
    │
    ▼
[Modulo 6] Rehydration Engine   Ripristino dati originali nella risposta
    │
    ▼
[Modulo 7] Validation Layer     Verifica token non sostituiti o inventati
    │
    ▼
Risposta finale con dati originali
```
