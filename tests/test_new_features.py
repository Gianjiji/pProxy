"""
Test di integrazione mirati alle NUOVE funzionalità dell'aggiornamento:

1. Tipi di entità estesi (documenti, identificativi, dati bancari/tecnici).
2. Rilevamento MULTILINGUE (IT/EN/ES/FR/PT/DE) di indirizzi, telefoni, codici.
3. Caricamento LAZY dei modelli NER (nessun caricamento alla costruzione, mai in
   modalità solo-regex).

Sono test deterministici basati solo sul `RuleBasedDetector` (regex + checksum) e
sullo stato del `NERDetector`: NON richiedono modelli NER installati e non li
caricano, quindi restano veloci.
"""
import pytest

from privacy_proxy import (
    RuleBasedDetector,
    NERDetector,
    SensitiveDataDetectionEngine,
    EntityType,
)


@pytest.fixture(scope="module")
def detector():
    return RuleBasedDetector()


def _types(detector, text):
    return {e.type.value for e in detector.detect(text)}


# ──────────────────────────────────────────────────────────────
# 1. Tipi di entità estesi (rilevatore deterministico)
# ──────────────────────────────────────────────────────────────

NEW_TYPE_CASES = [
    ("Passaporto: YA1234567", "PASSPORT"),
    ("DNI 12345678Z", "ID_CARD"),
    ("Patente di guida: MI1234567X", "DRIVING_LICENSE"),
    ("Targa AB123CD", "PLATE"),
    ("BIC UNCRITMMXXX", "BIC"),
    ("CVV: 123", "CVV"),
    ("Scadenza 12/27", "CARD_EXPIRY"),
    ("Server 192.168.1.100 attivo", "IP"),
    ("IPv6 2001:0db8:85a3:0000:0000:8a2e:0370:7334 ok", "IP"),
    ("MAC 00:1A:2B:3C:4D:5E", "MAC"),
    ("Visita https://www.example.com/path oggi", "URL"),
    ("Usuario: pedro123", "USERNAME"),
    ("Matricola: 0012345", "EMPLOYEE_ID"),
    ("Codice MED-123456 paziente", "MEDICAL_ID"),
    ("Numero polizza 998877", "INSURANCE_ID"),
    ("SSN: 123-45-6789", "TAX_ID"),
]


class TestExtendedEntityTypes:

    @pytest.mark.parametrize("text,expected", NEW_TYPE_CASES)
    def test_new_type_detected(self, detector, text, expected):
        assert expected in _types(detector, text), f"{expected} non rilevato in {text!r}"

    def test_all_new_types_exist_in_enum(self):
        # I nuovi tipi devono esistere nell'enum (contratto del filtro entity_types).
        for code in {"PASSPORT", "ID_CARD", "DRIVING_LICENSE", "PLATE", "BIC", "CVV",
                     "CARD_EXPIRY", "IP", "MAC", "URL", "USERNAME", "EMPLOYEE_ID",
                     "MEDICAL_ID", "INSURANCE_ID", "TAX_ID"}:
            assert any(e.value == code for e in EntityType), f"manca EntityType {code}"

    def test_cvv_validated_card_still_uses_luhn(self, detector):
        # Una carta valida (Luhn) resta rilevata come CARD anche tra i nuovi tipi.
        assert "CARD" in _types(detector, "Carta 4111 1111 1111 1111")


# ──────────────────────────────────────────────────────────────
# 2. Rilevamento multilingue (IT/EN/ES/FR/PT/DE)
# ──────────────────────────────────────────────────────────────

MULTILINGUAL_CASES = [
    # Spagnolo
    ("es-addr", "Calle Mayor 12, Madrid", "ADDR"),
    ("es-email", "Correo: juan.perez@example.es", "EMAIL"),
    ("es-insurance", "Número de póliza: 998877", "INSURANCE_ID"),
    # Francese
    ("fr-addr", "Rue de la Paix 5", "ADDR"),
    ("fr-phone", "Téléphone: +33 6 12 34 56 78", "PHONE"),
    ("fr-tax", "Numéro fiscal: FR12345678901", "TAX_ID"),
    # Portoghese
    ("pt-addr", "Morada: Rua Augusta 100, Lisboa", "ADDR"),
    ("pt-phone", "Telefone: +351 912 345 678", "PHONE"),
    # Tedesco
    ("de-addr", "Adresse: Hauptstraße 5, Berlin", "ADDR"),
    ("de-phone", "Telefon: +49 30 12345678", "PHONE"),
    ("de-tax", "Steuernummer: DE123456789", "TAX_ID"),
    ("de-idcard", "Personalausweis: T22000129", "ID_CARD"),
]


class TestMultilingualDetection:

    @pytest.mark.parametrize("name,text,expected", MULTILINGUAL_CASES,
                             ids=[c[0] for c in MULTILINGUAL_CASES])
    def test_language_specific_detection(self, detector, name, text, expected):
        assert expected in _types(detector, text), f"{expected} non rilevato in {text!r}"

    def test_no_false_positives_on_neutral_multilingual_text(self, detector):
        neutral = ("Buenos días, espero que estén todos bien. "
                   "Merci beaucoup pour votre aide. Vielen Dank für alles. "
                   "Thank you very much. Obrigado a todos.")
        assert _types(detector, neutral) == set()

    def test_german_strasse_address_value(self, detector):
        ents = detector.detect("Adresse: Hauptstraße 5, Berlin")
        addrs = [e.value for e in ents if e.type.value == "ADDR"]
        assert addrs and "Hauptstraße" in addrs[0]


# ──────────────────────────────────────────────────────────────
# 3. Caricamento lazy del NER
# ──────────────────────────────────────────────────────────────

class TestLazyNERLoading:

    def test_construction_does_not_load_models(self):
        n = NERDetector()
        assert n._loaded is False
        assert n._spacy_nlp is None
        assert n._presidio is None
        assert n._gliner is None

    def test_ensure_loaded_runs_each_loader_once_and_is_idempotent(self, monkeypatch):
        n = NERDetector()
        calls = {"spacy": 0, "presidio": 0, "gliner": 0}
        monkeypatch.setattr(n, "_load_spacy", lambda: calls.__setitem__("spacy", calls["spacy"] + 1))
        monkeypatch.setattr(n, "_load_presidio", lambda: calls.__setitem__("presidio", calls["presidio"] + 1))
        monkeypatch.setattr(n, "_load_gliner", lambda: calls.__setitem__("gliner", calls["gliner"] + 1))

        n._ensure_loaded()
        assert n._loaded is True
        n._ensure_loaded()  # seconda chiamata: nessun ricaricamento

        assert calls == {"spacy": 1, "presidio": 1, "gliner": 1}

    def test_regex_only_engine_has_no_ner_detector(self):
        engine = SensitiveDataDetectionEngine(use_ner=False)
        assert engine._ner is None
        # E rileva comunque i dati via regex, senza caricare alcun modello.
        types = {e.type.value for e in engine.detect(
            "Email mario@example.com, IBAN IT60X0542811101000000123456")}
        assert {"EMAIL", "IBAN"} <= types

    def test_ner_engine_defers_loading_until_first_detect(self):
        engine = SensitiveDataDetectionEngine(use_ner=True)
        assert isinstance(engine._ner, NERDetector)
        assert engine._ner._loaded is False  # costruito ma non ancora caricato
