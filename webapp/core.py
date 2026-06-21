"""
Adattatore tra la web app e il motore esistente in `pProxy.py`.

RIUSA i componenti del motore (detection, tokenization, rehydration, validation,
gateway LLM) senza duplicarne la logica. Differenza CHIAVE rispetto alla CLI:
qui NON si usa mai `InputLayer.load()`. In un server quel metodo, ricevendo come
"source" una stringa che coincide con un path esistente, leggerebbe quel file dal
filesystem del server (rischio di local file read / path traversal). La web app
tratta l'input SEMPRE e SOLO come testo, operando direttamente sui componenti.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from pProxy import (
    InputLayer,
    LLMGateway,
    LLMProvider,
    RehydrationEngine,
    SensitiveDataDetectionEngine,
    TokenizationEngine,
    ValidationLayer,
    _parse_entity_types,
)

# Estensioni di file ammesse per l'upload (i parser corrispondenti sono nel
# motore; PDF/CSV/DOCX richiedono dipendenze opzionali e, se assenti, producono
# un errore gestito).
ALLOWED_UPLOAD_SUFFIXES = {".txt", ".json", ".csv", ".pdf", ".docx"}

# Errori "attesi" (input/configurazione) da mappare su 4xx a livello API.
EngineInputError = (ValueError, ImportError)


class ProviderError(Exception):
    """Errore proveniente dal gateway LLM con messaggio già SANITIZZATO.

    Le librerie dei provider possono sollevare eccezioni il cui messaggio
    contiene frammenti del prompt (quindi dati anonimizzati) o dettagli interni.
    Avvolgendole qui con un messaggio che espone solo il tipo/un'etichetta
    generica, l'API può restituirlo al client senza rischio di leak.
    """


def extract_text_from_upload(filename: str, data: bytes) -> str:
    """Estrae testo da un file caricato, riusando i parser del motore.

    Sicurezza: i byte vengono scritti in un file temporaneo SERVER-CONTROLLED e
    `InputLayer.load` opera su QUEL percorso. Così si riusano i parser
    (PDF/CSV/DOCX/JSON/TXT) senza che un input dell'utente possa indicare un path
    arbitrario del server (nessun local file read / path traversal).
    """
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_UPLOAD_SUFFIXES:
        raise ValueError(
            f"Formato non supportato: {suffix or '(nessuna estensione)'}. "
            f"Ammessi: {', '.join(sorted(ALLOWED_UPLOAD_SUFFIXES))}"
        )
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        return InputLayer().load(tmp_path).text
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


def parse_entity_types(types: Optional[List[str]]):
    """Converte una lista di tipi entità in lista EntityType (None = tutti)."""
    if not types:
        return None
    return _parse_entity_types(",".join(types))


def _entities_payload(entities, include_values: bool) -> List[Dict[str, Any]]:
    """Serializza le entità rilevate. I valori originali sono inclusi solo su
    richiesta esplicita (default: no), per non esporre dati sensibili nelle
    risposte/log per impostazione predefinita."""
    out = []
    for e in entities:
        item = {
            "type": e.type.value,
            "confidence": round(e.confidence, 3),
            "source": e.source,
            "start": e.start,
            "end": e.end,
        }
        if include_values:
            item["value"] = e.value
        out.append(item)
    return out


def anonymize(
    text: str,
    *,
    confidence: float = 0.7,
    use_ner: bool = False,
    entity_types: Optional[List[str]] = None,
    include_values: bool = False,
) -> Dict[str, Any]:
    """Rileva e anonimizza il testo. Restituisce testo anonimizzato, mappa
    (placeholder→originale, da NON esporre al client), entità e validazione."""
    detector = SensitiveDataDetectionEngine(
        confidence_threshold=confidence,
        use_ner=use_ner,
        entity_types=parse_entity_types(entity_types),
    )
    entities = detector.detect(text)

    tokenizer = TokenizationEngine()
    anon_text, entity_map = tokenizer.tokenize(text, entities)

    validation = ValidationLayer().validate_anonymized(anon_text, entity_map)
    return {
        "anonymized_text": anon_text,
        "entity_map": entity_map,
        "entities": _entities_payload(entities, include_values),
        "validation": {
            "is_valid": validation.is_valid,
            "warnings": validation.warnings,
            "errors": validation.errors,
        },
    }


def rehydrate(text: str, mapping: Dict[str, str]) -> Dict[str, Any]:
    """Ripristina i dati originali nei placeholder usando la mappa di sessione."""
    rehydrated = RehydrationEngine().rehydrate(text, mapping)
    validation = ValidationLayer().validate_rehydrated(rehydrated, mapping)
    return {
        "rehydrated_text": rehydrated,
        "validation": {
            "is_valid": validation.is_valid,
            "warnings": validation.warnings,
            "errors": validation.errors,
        },
    }


def run_pipeline(
    text: str,
    *,
    prompt_template: str = "Analizza il seguente testo:\n\n{document}",
    provider: str = "demo",
    system_prompt: Optional[str] = None,
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    confidence: float = 0.7,
    use_ner: bool = False,
    entity_types: Optional[List[str]] = None,
    ollama_base_url: str = "http://localhost:11434",
    max_chunk_chars: int = 12_000,
    stop_on_error: bool = True,
) -> Dict[str, Any]:
    """Pipeline completa: anonimizza → LLM → ripristina, riusando il gateway esistente.

    La validazione di sicurezza dell'anonimizzazione blocca l'invio all'LLM se
    rileva un possibile leak (come la CLI con stop_on_error=True).
    """
    anon = anonymize(
        text, confidence=confidence, use_ner=use_ner, entity_types=entity_types
    )
    entity_map = anon["entity_map"]

    if stop_on_error and not anon["validation"]["is_valid"]:
        raise RuntimeError(
            "Anonimizzazione non sicura: pipeline interrotta prima dell'invio all'LLM."
        )

    gateway = LLMGateway(
        provider=LLMProvider(provider),
        api_key=api_key,
        model=model,
        base_url=ollama_base_url,
        max_chunk_chars=max_chunk_chars,
    )
    try:
        llm_response = gateway.send_document(
            anon["anonymized_text"], prompt_template, system_prompt
        )
    except ImportError as exc:
        raise ProviderError(f"Provider '{provider}' non disponibile sul server") from exc
    except Exception as exc:
        # Messaggio sanitizzato: solo il tipo dell'eccezione, mai il suo testo
        # (che potrebbe contenere frammenti del prompt anonimizzato).
        raise ProviderError(
            f"Errore dal provider LLM ({type(exc).__name__})"
        ) from exc

    rh = rehydrate(llm_response, entity_map)
    return {
        "anonymized_text": anon["anonymized_text"],
        "entity_map": entity_map,
        "entities": anon["entities"],
        "llm_response_anonymized": llm_response,
        "final_response": rh["rehydrated_text"],
        "validation": {
            "anonymization": anon["validation"],
            "rehydration": rh["validation"],
        },
    }
