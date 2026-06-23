"""
Test di integrazione per la NUOVA localizzazione dell'interfaccia (IT/EN/ES/FR/PT/DE).

Verificano che l'artefatto servito (`/static/i18n.js`) sia raggiungibile, collegato
da entrambe le pagine, copra le 6 lingue e abbia una tabella di traduzioni completa
(nessuna lingua lasciata a metà). Inoltre che `app.js` instradi i messaggi dinamici
attraverso il runtime di traduzione. Sono test client-side puri (nessun modello NER).
"""
import re

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from webapp.app import app  # noqa: E402

client = TestClient(app)

SUPPORTED_LANGS = ["it", "en", "es", "fr", "pt", "de"]


@pytest.fixture(scope="module")
def i18n_js():
    r = client.get("/static/i18n.js")
    assert r.status_code == 200
    return r.text


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def _translation_keys(js: str):
    """Estrae le chiavi italiane (template-literal) della tabella STRINGS."""
    return [_norm(k.replace("\\n", "\n").replace("\\`", "`").replace("\\'", "'"))
            for k in re.findall(r"\n\s*\[`((?:[^`\\]|\\.)*)`\]:", js)]


# ──────────────────────────────────────────────────────────────
# Artefatto servito e collegamenti nelle pagine
# ──────────────────────────────────────────────────────────────

class TestI18nAssetWiring:

    def test_i18n_js_served_with_runtime(self, i18n_js):
        assert "i18nT" in i18n_js
        assert "STRINGS" in i18n_js

    def test_index_links_i18n(self):
        html = client.get("/").text
        assert "/static/i18n.js" in html
        # Deve essere caricato PRIMA di app.js (definisce window.i18nT).
        assert html.index("/static/i18n.js") < html.index("/static/app.js")

    def test_guide_links_i18n(self):
        assert "/static/i18n.js" in client.get("/guida").text

    def test_app_js_routes_dynamic_strings_through_runtime(self):
        app_js = client.get("/static/app.js").text
        assert "window.i18nT" in app_js
        # I messaggi dinamici passano dall'helper tt(...).
        assert 'tt("Fatto.")' in app_js or "tt('Fatto.')" in app_js


# ──────────────────────────────────────────────────────────────
# Copertura della tabella di traduzioni
# ──────────────────────────────────────────────────────────────

class TestTranslationTable:

    def test_selector_offers_all_six_languages(self, i18n_js):
        for code in SUPPORTED_LANGS:
            assert f'["{code}",' in i18n_js or f'"{code}",' in i18n_js, f"lingua {code} assente dal selettore"

    def test_every_key_has_all_five_translations(self, i18n_js):
        # Ogni voce STRINGS deve avere 5 traduzioni (en,es,fr,pt,de) non vuote.
        entries = re.findall(r"\]:\s*\[((?:[^\[\]]|\\.)*?)\]", i18n_js, re.DOTALL)
        assert entries, "nessuna voce STRINGS trovata"
        incomplete = []
        for body in entries:
            parts = re.findall(r"`((?:[^`\\]|\\.)*)`", body)
            if len(parts) != 5 or any(not p.strip() for p in parts):
                incomplete.append(body[:50])
        assert not incomplete, f"voci con traduzioni mancanti/incomplete: {incomplete}"

    def test_core_ui_strings_are_translated(self, i18n_js):
        keys = set(_translation_keys(i18n_js))
        # Campione rappresentativo di stringhe UNICHE (statiche + dinamiche).
        sample = [
            "📖 Guida", "1 · Anonimizza", "Pipeline LLM", "Sessioni", "Opzioni",
            "Confidenza", "Tipi entità", "NER avanzato", "Anonimizza", "Copia",
            "Provider", "Modello", "Esegui pipeline", "Stato", "Elimina",
            "Guida a pProxy", "A cosa serve", "Le opzioni",
            "Copiato negli appunti.", "Elaborazione…", "Fatto.", "entità",
            "Sessione eliminata.",
        ]
        missing = [s for s in sample if _norm(s) not in keys]
        assert not missing, f"stringhe UI senza traduzione: {missing}"

    def test_guide_page_strings_covered(self, i18n_js):
        # Le intestazioni della guida devono essere tutte tradotte.
        keys = set(_translation_keys(i18n_js))
        for h in ["I due modi di usarlo", "Modalità zero-knowledge",
                  "API key dell'app", "Tipi di dato riconosciuti",
                  "Per chi usa l'API direttamente"]:
            assert _norm(h) in keys, f"intestazione guida non tradotta: {h!r}"
