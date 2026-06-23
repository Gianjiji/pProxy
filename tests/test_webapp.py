"""
Test della web app pProxy (FastAPI).

Coprono: endpoint principali, ciclo di vita delle sessioni e — soprattutto — le
proprietà di PRIVACY: la mappa/i dati originali non devono mai trapelare nelle
risposte non esplicite, e l'input non deve mai essere interpretato come file del
server.
"""

import time

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from webapp.app import app, rate_limiter, store  # noqa: E402
from webapp.ratelimit import RateLimiter  # noqa: E402
from webapp.sessions import SessionStore  # noqa: E402

client = TestClient(app)

SENSITIVE = "Scrivi a mario.rossi@example.com, tel +39 333 1234567"


@pytest.fixture(autouse=True)
def _clear_state():
    # Isola lo stato tra i test (sessioni + contatori rate limit).
    for sid in list(store._sessions):  # noqa: SLF001 (test interno)
        store.delete(sid)
    rate_limiter.reset()
    yield
    rate_limiter.reset()


# ── Autenticazione opzionale (API key) ───────────────────────

def test_auth_disabled_by_default():
    """Senza PPROXY_API_KEY configurata, gli endpoint restano aperti."""
    import webapp.app as appmod
    assert appmod.API_KEY == ""  # default off
    assert client.post("/api/anonymize", json={"text": "a@b.com", "use_ner": False}).status_code == 200


def test_auth_enabled_requires_key(monkeypatch):
    import webapp.app as appmod
    monkeypatch.setattr(appmod, "API_KEY", "segreta")
    # senza header → 401 (con header di sicurezza)
    r = client.post("/api/anonymize", json={"text": "a@b.com", "use_ner": False})
    assert r.status_code == 401
    assert r.headers["x-content-type-options"] == "nosniff"
    # chiave errata → 401
    r2 = client.post(
        "/api/anonymize", json={"text": "a@b.com", "use_ner": False},
        headers={"X-API-Key": "sbagliata"},
    )
    assert r2.status_code == 401
    # chiave corretta → 200
    r3 = client.post(
        "/api/anonymize", json={"text": "a@b.com", "use_ner": False},
        headers={"X-API-Key": "segreta"},
    )
    assert r3.status_code == 200


def test_auth_enabled_health_and_ui_stay_open(monkeypatch):
    import webapp.app as appmod
    monkeypatch.setattr(appmod, "API_KEY", "segreta")
    assert client.get("/api/health").status_code == 200   # liveness aperto
    assert client.get("/").status_code == 200             # UI aperta


def test_auth_does_not_block_cors_preflight(monkeypatch):
    """Regressione: con auth attiva, il preflight CORS (OPTIONS, senza X-API-Key)
    NON deve ricevere 401 — altrimenti i client cross-origin via browser si rompono."""
    import webapp.app as appmod
    monkeypatch.setattr(appmod, "API_KEY", "segreta")
    r = client.options(
        "/api/anonymize",
        headers={"Origin": "https://x.com", "Access-Control-Request-Method": "POST"},
    )
    assert r.status_code != 401                            # preflight passa oltre l'auth
    # la POST reale senza chiave resta protetta
    assert client.post("/api/anonymize", json={"text": "a@b.com"}).status_code == 401


# ── Allowlist provider ───────────────────────────────────────

def test_provider_allowlist_disabled_by_default():
    import webapp.app as appmod
    assert appmod.ALLOWED_PROVIDERS == set()  # default: tutti ammessi
    r = client.post("/api/process", json={"text": "a@b.com", "provider": "demo", "use_ner": False})
    assert r.status_code == 200


def test_provider_not_in_allowlist_forbidden(monkeypatch):
    import webapp.app as appmod
    monkeypatch.setattr(appmod, "ALLOWED_PROVIDERS", {"ollama"})  # demo non incluso
    r = client.post("/api/process", json={"text": "a@b.com", "provider": "demo", "use_ner": False})
    assert r.status_code == 403
    # provider consentito → ok
    monkeypatch.setattr(appmod, "ALLOWED_PROVIDERS", {"demo"})
    r2 = client.post("/api/process", json={"text": "a@b.com", "provider": "demo", "use_ner": False})
    assert r2.status_code == 200


def test_provider_allowlist_applies_to_process_file(monkeypatch):
    import webapp.app as appmod
    monkeypatch.setattr(appmod, "ALLOWED_PROVIDERS", {"ollama"})
    files = {"file": ("d.txt", b"a@b.com", "text/plain")}
    r = client.post("/api/process-file", files=files, data={"provider": "demo"})
    assert r.status_code == 403


# ── Osservabilità (X-Request-ID + access log) ────────────────

def test_request_id_header_present_and_generated():
    r = client.get("/api/health")
    assert r.headers.get("x-request-id")


def test_request_id_echoed_when_provided():
    r = client.get("/api/health", headers={"X-Request-ID": "abc123"})
    assert r.headers["x-request-id"] == "abc123"


def test_access_log_redacts_session_id_and_no_sensitive_data(caplog):
    import logging

    a = client.post("/api/anonymize", json={"text": SENSITIVE, "use_ner": False}).json()
    sid = a["session_id"]
    with caplog.at_level(logging.INFO, logger="pproxy.webapp.access"):
        client.get(f"/api/session/{sid}")
    log = caplog.text
    assert "/api/session/<id>" in log     # path redatto
    assert sid not in log                  # niente capability nei log
    assert "mario.rossi@example.com" not in log


# ── Health ───────────────────────────────────────────────────

def test_health_ok():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_documented_startup_target_importable():
    """Il target documentato (Docker/uvicorn) 'webapp.app:app' deve esistere
    ed essere un'app ASGI FastAPI."""
    import importlib

    from fastapi import FastAPI

    mod = importlib.import_module("webapp.app")
    assert isinstance(getattr(mod, "app"), FastAPI)


def test_openapi_has_tags_and_summaries():
    """Gli endpoint sono documentati (tag + summary) nello schema OpenAPI."""
    spec = client.get("/openapi.json").json()
    paths = spec["paths"]
    # process è taggato 'pipeline' con un summary
    op = paths["/api/process"]["post"]
    assert "pipeline" in op.get("tags", [])
    assert op.get("summary")
    # ogni endpoint /api ha almeno un tag
    for path, methods in paths.items():
        if path.startswith("/api/"):
            for method, op in methods.items():
                assert op.get("tags"), f"{method.upper()} {path} senza tag"


def test_module_launcher_exists():
    """`python -m webapp` deve avere un entrypoint main() invocabile."""
    import importlib

    m = importlib.import_module("webapp.__main__")
    assert callable(getattr(m, "main"))


# ── Anonymize ────────────────────────────────────────────────

def test_anonymize_returns_placeholders_and_session():
    r = client.post("/api/anonymize", json={"text": SENSITIVE, "use_ner": False})
    assert r.status_code == 200
    data = r.json()
    assert "[EMAIL_001]" in data["anonymized_text"]
    assert "[PHONE_001]" in data["anonymized_text"]
    assert data["session_id"]
    assert data["entity_count"] >= 2


def test_anonymize_never_leaks_mapping_or_values_by_default():
    r = client.post("/api/anonymize", json={"text": SENSITIVE, "use_ner": False})
    body = r.text
    # Né i valori originali né la mappa devono comparire nella risposta.
    assert "mario.rossi@example.com" not in body
    assert "+39 333 1234567" not in body
    assert "entity_map" not in r.json()
    for ent in r.json()["entities"]:
        assert "value" not in ent  # valori esclusi per default


def test_anonymize_include_values_opt_in():
    r = client.post(
        "/api/anonymize",
        json={"text": SENSITIVE, "use_ner": False, "include_values": True},
    )
    values = [e.get("value") for e in r.json()["entities"]]
    assert "mario.rossi@example.com" in values


def test_anonymize_input_is_never_read_as_file(tmp_path):
    """Regressione di sicurezza: passare un path esistente NON deve far leggere
    il file dal server. Il testo è trattato letteralmente."""
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("TOP-SECRET-CONTENT-XYZ", encoding="utf-8")
    r = client.post("/api/anonymize", json={"text": str(secret_file), "use_ner": False})
    assert r.status_code == 200
    assert "TOP-SECRET-CONTENT-XYZ" not in r.text


# ── Rehydrate ────────────────────────────────────────────────

def test_rehydrate_restores_original_via_session():
    a = client.post("/api/anonymize", json={"text": SENSITIVE, "use_ner": False}).json()
    sid = a["session_id"]
    anon = a["anonymized_text"]
    r = client.post("/api/rehydrate", json={"text": anon, "session_id": sid})
    assert r.status_code == 200
    restored = r.json()["rehydrated_text"]
    assert "mario.rossi@example.com" in restored
    assert "+39 333 1234567" in restored


def test_rehydrate_unknown_session_returns_404():
    r = client.post(
        "/api/rehydrate", json={"text": "[EMAIL_001]", "session_id": "inesistente"}
    )
    assert r.status_code == 404


# ── Process (pipeline completa via demo) ─────────────────────

def test_process_demo_end_to_end():
    r = client.post(
        "/api/process",
        json={"text": SENSITIVE, "provider": "demo", "use_ner": False},
    )
    assert r.status_code == 200
    data = r.json()
    assert "[EMAIL_001]" in data["anonymized_text"]
    # il provider demo riecheggia i placeholder → la rehydration ripristina l'originale
    assert "mario.rossi@example.com" in data["final_response"]
    assert data["session_id"]


# ── Lifecycle sessione ───────────────────────────────────────

def test_session_status_returns_metadata_only():
    a = client.post("/api/anonymize", json={"text": SENSITIVE, "use_ner": False}).json()
    sid = a["session_id"]
    r = client.get(f"/api/session/{sid}")
    assert r.status_code == 200
    data = r.json()
    assert data["active"] is True
    assert data["entity_count"] >= 2
    assert 0 < data["expires_in"] <= 1800
    # lo stato NON deve esporre mappa/valori originali
    assert "mapping" not in data
    assert "mario.rossi@example.com" not in r.text


def test_session_status_unknown_404():
    assert client.get("/api/session/nope").status_code == 404


def test_session_status_after_delete_404():
    a = client.post("/api/anonymize", json={"text": SENSITIVE, "use_ner": False}).json()
    sid = a["session_id"]
    client.delete(f"/api/session/{sid}")
    assert client.get(f"/api/session/{sid}").status_code == 404


def test_delete_session_then_rehydrate_fails():
    a = client.post("/api/anonymize", json={"text": SENSITIVE, "use_ner": False}).json()
    sid = a["session_id"]
    d = client.delete(f"/api/session/{sid}")
    assert d.status_code == 200 and d.json()["deleted"] is True
    r = client.post("/api/rehydrate", json={"text": a["anonymized_text"], "session_id": sid})
    assert r.status_code == 404


def test_delete_unknown_session_404():
    assert client.delete("/api/session/nope").status_code == 404


# ── Validazione input ────────────────────────────────────────

def test_empty_text_rejected():
    assert client.post("/api/anonymize", json={"text": ""}).status_code == 422


def test_oversize_text_rejected():
    big = "a" * 200_001
    assert client.post("/api/anonymize", json={"text": big}).status_code == 422


def test_oversize_body_rejected_413(monkeypatch):
    """Un body oltre MAX_BODY_BYTES è rifiutato (413) prima del parsing, con
    header di sicurezza presenti."""
    import webapp.app as appmod
    monkeypatch.setattr(appmod, "MAX_BODY_BYTES", 100)
    r = client.post("/api/anonymize", json={"text": "x" * 500})
    assert r.status_code == 413
    assert r.headers["x-content-type-options"] == "nosniff"  # header anche sul 413


# ── Upload file ──────────────────────────────────────────────

def test_upload_txt_anonymizes():
    files = {"file": ("doc.txt", SENSITIVE.encode("utf-8"), "text/plain")}
    r = client.post("/api/anonymize-file", files=files, data={"use_ner": "false"})
    assert r.status_code == 200
    data = r.json()
    assert "[EMAIL_001]" in data["anonymized_text"]
    assert data["session_id"]


def test_upload_json_anonymizes():
    payload = '{"email": "mario.rossi@example.com", "tel": "+39 333 1234567"}'
    files = {"file": ("d.json", payload.encode("utf-8"), "application/json")}
    r = client.post("/api/anonymize-file", files=files, data={"use_ner": "false"})
    assert r.status_code == 200
    assert "[EMAIL_001]" in r.json()["anonymized_text"]


def test_upload_unsupported_extension_400():
    files = {"file": ("malware.exe", b"data", "application/octet-stream")}
    r = client.post("/api/anonymize-file", files=files)
    assert r.status_code == 400
    assert "Formato non supportato" in r.json()["detail"]


def test_upload_empty_file_400():
    files = {"file": ("d.txt", b"", "text/plain")}
    r = client.post("/api/anonymize-file", files=files)
    assert r.status_code == 400


def test_upload_oversize_413(monkeypatch):
    import webapp.app as appmod
    monkeypatch.setattr(appmod, "MAX_UPLOAD_BYTES", 10)
    files = {"file": ("d.txt", b"x" * 50, "text/plain")}
    r = client.post("/api/anonymize-file", files=files)
    assert r.status_code == 413


def test_upload_stateless_returns_mapping_no_session():
    before = len(store)
    files = {"file": ("d.txt", SENSITIVE.encode("utf-8"), "text/plain")}
    r = client.post(
        "/api/anonymize-file", files=files, data={"use_ner": "false", "stateless": "true"}
    )
    assert r.status_code == 200
    assert r.json()["session_id"] is None
    assert r.json()["mapping"]
    assert len(store) == before


def test_process_file_demo_end_to_end():
    files = {"file": ("doc.txt", SENSITIVE.encode("utf-8"), "text/plain")}
    r = client.post(
        "/api/process-file", files=files, data={"provider": "demo", "use_ner": "false"}
    )
    assert r.status_code == 200
    data = r.json()
    assert "[EMAIL_001]" in data["anonymized_text"]
    assert "mario.rossi@example.com" in data["final_response"]  # ripristinato
    assert data["session_id"]


def test_process_file_unsupported_extension_400():
    files = {"file": ("x.exe", b"data", "application/octet-stream")}
    r = client.post("/api/process-file", files=files, data={"provider": "demo"})
    assert r.status_code == 400


def test_process_file_oversize_413(monkeypatch):
    import webapp.app as appmod
    monkeypatch.setattr(appmod, "MAX_UPLOAD_BYTES", 10)
    files = {"file": ("d.txt", b"x" * 50, "text/plain")}
    r = client.post("/api/process-file", files=files, data={"provider": "demo"})
    assert r.status_code == 413


def test_process_file_stateless_no_session():
    before = len(store)
    files = {"file": ("d.txt", SENSITIVE.encode("utf-8"), "text/plain")}
    r = client.post(
        "/api/process-file",
        files=files,
        data={"provider": "demo", "use_ner": "false", "stateless": "true"},
    )
    assert r.status_code == 200
    assert r.json()["session_id"] is None
    assert len(store) == before


def test_upload_content_is_not_read_as_server_path(tmp_path):
    """Il contenuto del file caricato NON deve indurre la lettura di un path del
    server: se il .txt contiene un percorso, viene trattato come testo."""
    secret = tmp_path / "s.txt"
    secret.write_text("RISERVATO-ABC", encoding="utf-8")
    files = {"file": ("p.txt", str(secret).encode("utf-8"), "text/plain")}
    r = client.post("/api/anonymize-file", files=files, data={"use_ner": "false"})
    assert r.status_code == 200
    assert "RISERVATO-ABC" not in r.text


# ── Zero-knowledge (server stateless) ────────────────────────

def test_stateless_anonymize_returns_map_and_no_session():
    before = len(store)
    r = client.post(
        "/api/anonymize",
        json={"text": SENSITIVE, "use_ner": False, "stateless": True},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["session_id"] is None
    assert "mapping" in data and data["mapping"]  # mappa restituita al client
    assert len(store) == before  # nessuna sessione creata lato server


def test_stateless_roundtrip_with_client_mapping():
    a = client.post(
        "/api/anonymize",
        json={"text": SENSITIVE, "use_ner": False, "stateless": True},
    ).json()
    r = client.post(
        "/api/rehydrate",
        json={"text": a["anonymized_text"], "mapping": a["mapping"]},
    )
    assert r.status_code == 200
    assert "mario.rossi@example.com" in r.json()["rehydrated_text"]


def test_default_anonymize_does_not_return_mapping():
    r = client.post("/api/anonymize", json={"text": SENSITIVE, "use_ner": False})
    data = r.json()
    assert data["session_id"]            # sessione lato server
    assert "mapping" not in data         # mappa NON restituita in modalità default


def test_rehydrate_requires_exactly_one_source():
    # né session_id né mapping → 400
    r1 = client.post("/api/rehydrate", json={"text": "[EMAIL_001]"})
    assert r1.status_code == 400
    # entrambi → 400
    r2 = client.post(
        "/api/rehydrate",
        json={"text": "[EMAIL_001]", "session_id": "x", "mapping": {"[EMAIL_001]": "y"}},
    )
    assert r2.status_code == 400


def test_stateless_process_creates_no_session():
    before = len(store)
    r = client.post(
        "/api/process",
        json={"text": SENSITIVE, "provider": "demo", "use_ner": False, "stateless": True},
    )
    assert r.status_code == 200
    assert r.json()["session_id"] is None
    assert len(store) == before


def test_process_prompt_with_braces_does_not_500():
    """Un prompt utente con graffe estranee (es. richiesta JSON) NON deve causare
    un 500/502: il template sostituisce solo {document}."""
    r = client.post(
        "/api/process",
        json={
            "text": "mario.rossi@example.com",
            "provider": "demo",
            "use_ner": False,
            "prompt": 'Rispondi in JSON: {"email": "{document}"}',
        },
    )
    assert r.status_code == 200
    assert "mario.rossi@example.com" in r.json()["final_response"]


# ── Robustezza & mappatura errori ────────────────────────────

def test_process_small_max_chunk_splits_long_document():
    """Con max_chunk piccolo, un documento lungo viene spezzato in più chunk
    (il provider demo etichetta '[Parte i di n]')."""
    long_text = ("mario.rossi@example.com " + "testo di riempimento. " * 40) * 4
    r = client.post(
        "/api/process",
        json={"text": long_text, "provider": "demo", "use_ner": False, "max_chunk": 200},
    )
    assert r.status_code == 200
    data = r.json()
    assert "[Parte 1 di" in data["final_response"]   # chunking avvenuto
    assert "mario.rossi@example.com" in data["final_response"]  # ripristino corretto


def test_process_max_chunk_zero_disables_chunking():
    long_text = "mario.rossi@example.com " + "riempimento " * 200
    r = client.post(
        "/api/process",
        json={"text": long_text, "provider": "demo", "use_ner": False, "max_chunk": 0},
    )
    assert r.status_code == 200
    # nessun chunking → nessuna etichetta di parte
    assert "[Parte" not in r.json()["final_response"]


def test_process_file_max_chunk_negative_422():
    files = {"file": ("d.txt", SENSITIVE.encode("utf-8"), "text/plain")}
    r = client.post(
        "/api/process-file", files=files, data={"provider": "demo", "max_chunk": "-5"}
    )
    assert r.status_code == 422


def test_process_invalid_provider_returns_400():
    r = client.post(
        "/api/process",
        json={"text": SENSITIVE, "provider": "bogus", "use_ner": False},
    )
    assert r.status_code == 400


def test_process_missing_provider_sdk_returns_502(monkeypatch):
    """SDK provider assente (ImportError) → 502 'non disponibile' (sanitizzato).

    Deterministico: si forza l'ImportError invece di dipendere da quali SDK siano
    installate nell'ambiente (che possono cambiare)."""
    from pProxy import LLMGateway

    def _no_sdk(self, *a, **k):
        raise ImportError("pip install anthropic")

    monkeypatch.setattr(LLMGateway, "send_document", _no_sdk)
    r = client.post(
        "/api/process",
        json={"text": SENSITIVE, "provider": "anthropic", "use_ner": False},
    )
    assert r.status_code == 502
    assert "non disponibile" in r.json()["detail"]
    assert "mario.rossi@example.com" not in r.text  # nessun dato sensibile nell'errore


def test_process_safety_stop_returns_422(monkeypatch):
    import webapp.app as appmod

    def _raise(*a, **k):
        raise RuntimeError("Anonimizzazione non sicura: pipeline interrotta.")

    monkeypatch.setattr(appmod, "run_pipeline", _raise)
    r = client.post("/api/process", json={"text": SENSITIVE, "provider": "demo"})
    assert r.status_code == 422


def test_upload_invalid_confidence_422():
    files = {"file": ("d.txt", SENSITIVE.encode("utf-8"), "text/plain")}
    r = client.post("/api/anonymize-file", files=files, data={"confidence": "2.0"})
    assert r.status_code == 422


def test_run_pipeline_safety_stop_blocks_llm(monkeypatch):
    """Se la validazione dell'anonimizzazione fallisce, la pipeline si interrompe
    PRIMA di inviare all'LLM (RuntimeError), proteggendo i dati."""
    import webapp.core as coremod

    class _Invalid:
        is_valid = False
        warnings: list = []
        errors = ["dato trapelato"]

    monkeypatch.setattr(
        coremod.ValidationLayer,
        "validate_anonymized",
        lambda self, *a, **k: _Invalid(),
    )
    with pytest.raises(RuntimeError):
        coremod.run_pipeline("mario.rossi@example.com", provider="demo")


# ── Sicurezza & privacy ──────────────────────────────────────

def test_security_headers_present():
    r = client.get("/api/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["cache-control"] == "no-store"
    assert "content-security-policy" in r.headers


def test_no_sensitive_value_in_logs(caplog):
    """La mappa/i dati originali non devono mai comparire nei log."""
    import logging

    with caplog.at_level(logging.DEBUG):
        r = client.post(
            "/api/process",
            json={"text": SENSITIVE, "provider": "demo", "use_ner": False},
        )
    assert r.status_code == 200
    assert "mario.rossi@example.com" not in caplog.text
    assert "+39 333 1234567" not in caplog.text


def test_provider_error_payload_is_sanitized(monkeypatch):
    """Se il provider solleva un'eccezione il cui messaggio contiene dati, il
    payload di errore 502 NON deve esporlo (solo messaggio sanitizzato)."""
    from pProxy import LLMGateway

    def _leaky_boom(self, *a, **k):
        raise ValueError("dettaglio interno con mario.rossi@example.com nel testo")

    monkeypatch.setattr(LLMGateway, "send_document", _leaky_boom)
    r = client.post(
        "/api/process", json={"text": SENSITIVE, "provider": "demo", "use_ner": False}
    )
    assert r.status_code == 502
    assert "mario.rossi@example.com" not in r.text
    assert "ValueError" in r.json()["detail"]


def test_invalid_entity_type_returns_clean_400():
    r = client.post(
        "/api/anonymize", json={"text": SENSITIVE, "entity_types": ["NONEXISTENT"]}
    )
    assert r.status_code == 400
    assert "NONEXISTENT" in r.json()["detail"]


class TestSecurityFeatureComposition:
    """Le leve di sicurezza opt-in (auth, allowlist provider, rate limit) devono
    comporsi correttamente quando abilitate insieme."""

    def test_auth_and_allowlist_together(self, monkeypatch):
        import webapp.app as appmod
        monkeypatch.setattr(appmod, "API_KEY", "k")
        monkeypatch.setattr(appmod, "ALLOWED_PROVIDERS", {"demo"})
        body = {"text": "a@b.com", "provider": "demo", "use_ner": False}
        # senza chiave → 401 (auth precede tutto il resto del routing)
        assert client.post("/api/process", json=body).status_code == 401
        # chiave ok ma provider non consentito → 403
        r = client.post(
            "/api/process",
            json={**body, "provider": "openai"},
            headers={"X-API-Key": "k"},
        )
        assert r.status_code == 403
        # chiave ok + provider consentito → 200
        r2 = client.post("/api/process", json=body, headers={"X-API-Key": "k"})
        assert r2.status_code == 200

    def test_rate_limit_applies_to_unauthenticated_requests(self, monkeypatch):
        """Brute-force protection: il rate limit conta anche le richieste non
        autenticate (rate-limit è più esterno di auth)."""
        import webapp.app as appmod
        monkeypatch.setattr(appmod, "API_KEY", "k")
        monkeypatch.setattr(appmod.rate_limiter, "max_requests", 3)
        appmod.rate_limiter.reset()
        codes = [
            client.post("/api/anonymize", json={"text": "a@b.com"}).status_code
            for _ in range(6)
        ]
        assert codes[:3] == [401, 401, 401]  # rate-limit permette, auth rifiuta
        assert 429 in codes                   # poi scatta il rate limit


def test_rate_limit_returns_429(monkeypatch):
    """Superata la soglia, il limiter deve rispondere 429 (con header di sicurezza)."""
    monkeypatch.setattr(rate_limiter, "max_requests", 3)
    rate_limiter.reset()
    codes = [client.get("/api/health").status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200]
    assert 429 in codes
    # gli header di sicurezza ci sono anche sulla risposta 429
    blocked = client.get("/api/health")
    assert blocked.status_code == 429
    assert blocked.headers["x-content-type-options"] == "nosniff"
    # RFC 6585: il 429 deve includere Retry-After (intero positivo di secondi)
    assert int(blocked.headers["retry-after"]) >= 1


class TestRateLimiter:
    def test_retry_after_positive_when_full_zero_when_free(self):
        rl = RateLimiter(max_requests=1, window_seconds=60)
        assert rl.retry_after("a") == 0       # ancora spazio
        assert rl.allow("a")
        assert not rl.allow("a")              # piena
        ra = rl.retry_after("a")
        assert 1 <= ra <= 61

    def test_allows_up_to_limit_then_blocks(self):
        rl = RateLimiter(max_requests=2, window_seconds=60)
        assert rl.allow("a") and rl.allow("a")
        assert not rl.allow("a")
        # chiave diversa = contatore indipendente
        assert rl.allow("b")

    def test_invalid_params_rejected(self):
        with pytest.raises(ValueError):
            RateLimiter(max_requests=0, window_seconds=60)
        with pytest.raises(ValueError):
            RateLimiter(max_requests=1, window_seconds=0)

    def test_sliding_window_frees_old_hits(self):
        rl = RateLimiter(max_requests=1, window_seconds=1)
        assert rl.allow("a")
        assert not rl.allow("a")
        time.sleep(1.05)
        # il timestamp vecchio esce dalla finestra → di nuovo consentito
        assert rl.allow("a")

    def test_reset_clears_counters(self):
        rl = RateLimiter(max_requests=1, window_seconds=60)
        assert rl.allow("a")
        assert not rl.allow("a")
        rl.reset()
        assert rl.allow("a")


# ── Eviction in background ───────────────────────────────────

def test_eviction_loop_calls_evict_periodically(monkeypatch):
    """Il loop in background invoca evict_expired a intervalli, anche senza richieste."""
    import asyncio

    import webapp.app as appmod

    calls = {"n": 0}

    def _counting_evict():
        calls["n"] += 1
        return 0

    monkeypatch.setattr(appmod.store, "evict_expired", _counting_evict)
    monkeypatch.setattr(appmod, "EVICT_INTERVAL", 0.01)

    async def _run():
        task = asyncio.create_task(appmod._eviction_loop())
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(_run())
    assert calls["n"] >= 1


def test_lifespan_startup_and_shutdown_clean():
    """Avvio/arresto con il task di eviction non devono sollevare errori."""
    with TestClient(app) as c:
        assert c.get("/api/health").status_code == 200


# ── UI statica ───────────────────────────────────────────────

def test_index_served():
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "pProxy" in r.text


def test_index_exposes_all_operations():
    """La UI deve esporre tutte le operazioni: anonimizza, ripristina, pipeline, sessioni."""
    html = client.get("/").text
    for marker in ('data-tab="anon"', 'data-tab="rehy"', 'data-tab="pipe"', 'data-tab="sess"'):
        assert marker in html
    assert 'href="/guida"' in html  # link alla guida


def test_guide_page_served():
    r = client.get("/guida")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "Guida" in r.text


def test_guide_uses_textcontent_safe_static():
    # la guida è statica e same-origin; deve essere servibile e referenziare lo stile
    assert "/static/style.css" in client.get("/guida").text


def test_favicon_no_404():
    r = client.get("/favicon.ico")
    # Il route serve l'icona se presente (200) o risponde 204 se manca: mai 404.
    assert r.status_code in (200, 204)
    assert r.status_code != 404


def test_static_assets_served():
    for path in ("/static/app.js", "/static/style.css"):
        r = client.get(path)
        assert r.status_code == 200


def test_csp_relaxed_for_ui_strict_for_api():
    ui = client.get("/").headers["content-security-policy"]
    api = client.get("/api/health").headers["content-security-policy"]
    assert "default-src 'self'" in ui          # la UI può caricare risorse same-origin
    assert "default-src 'none'" in api          # l'API no


def test_frontend_has_no_unsafe_dom_sinks():
    """Guardia XSS: la UI scrive gli output (testo LLM/dati ripristinati) solo via
    textContent. Nessun sink che interpreta HTML deve comparire in app.js."""
    from pathlib import Path

    import webapp

    js = (Path(webapp.__file__).parent / "static" / "app.js").read_text(encoding="utf-8")
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
        assert sink not in js, f"possibile sink XSS introdotto: {sink}"


# ── SessionStore (unità) ─────────────────────────────────────

class TestSessionStore:

    def test_invalid_ttl_rejected(self):
        with pytest.raises(ValueError):
            SessionStore(ttl_seconds=0)

    def test_ids_are_unpredictable_and_unique(self):
        s = SessionStore()
        ids = {s.create({"[E_001]": "x"}) for _ in range(50)}
        assert len(ids) == 50
        assert all(len(i) >= 32 for i in ids)

    def test_ttl_expiry(self):
        s = SessionStore(ttl_seconds=1)
        sid = s.create({"[E_001]": "x"})
        assert s.get_mapping(sid) is not None
        time.sleep(1.1)
        assert s.get_mapping(sid) is None

    def test_evict_expired(self):
        s = SessionStore(ttl_seconds=1)
        s.create({"[E_001]": "x"})
        time.sleep(1.1)
        assert s.evict_expired() == 1
        assert len(s) == 0

    def test_get_returns_copy_not_reference(self):
        s = SessionStore()
        sid = s.create({"[E_001]": "orig"})
        m = s.get_mapping(sid)
        m["[E_001]"] = "tampered"
        assert s.get_mapping(sid)["[E_001]"] == "orig"

    def test_status_metadata_and_expiry(self):
        s = SessionStore(ttl_seconds=1)
        sid = s.create({"[E_001]": "x", "[E_002]": "y"})
        st = s.status(sid)
        assert st is not None and st["entity_count"] == 2
        time.sleep(1.05)
        assert s.status(sid) is None  # scaduta


class TestConcurrency:
    """SessionStore e RateLimiter sono acceduti in parallelo dal threadpool ASGI
    per gli endpoint sincroni: questi test verificano la thread-safety dei lock."""

    def test_ratelimiter_no_over_admission_under_threads(self):
        from concurrent.futures import ThreadPoolExecutor

        rl = RateLimiter(max_requests=100, window_seconds=60)
        with ThreadPoolExecutor(max_workers=20) as ex:
            results = list(ex.map(lambda _: rl.allow("k"), range(2000)))
        # Esattamente max_requests ammessi: il lock impedisce over-admission.
        assert sum(results) == 100

    def test_sessionstore_concurrent_create_unique(self):
        from concurrent.futures import ThreadPoolExecutor

        s = SessionStore()
        with ThreadPoolExecutor(max_workers=20) as ex:
            ids = list(ex.map(lambda i: s.create({"[E_001]": str(i)}), range(500)))
        assert len(set(ids)) == 500   # nessuna collisione/ID perso
        assert len(s) == 500

    def test_sessionstore_concurrent_mixed_ops_no_errors(self):
        from concurrent.futures import ThreadPoolExecutor

        s = SessionStore()
        sids = [s.create({"[E_001]": "x"}) for _ in range(200)]

        def op(i):
            sid = sids[i % len(sids)]
            s.get_mapping(sid)
            s.status(sid)
            if i % 5 == 0:
                s.delete(sid)
            return True

        with ThreadPoolExecutor(max_workers=16) as ex:
            assert all(ex.map(op, range(3000)))
