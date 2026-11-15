"""Sicurezza della mappa placeholder → originale.

La mappa è il file più delicato prodotto dallo strumento: contiene in chiaro tutti i
dati che l'anonimizzazione ha tolto dal testo. Questi test fissano quattro garanzie:

  1. cifratura *fail-closed*: se è richiesta ma non è possibile, niente file in chiaro;
  2. file privato (0600) e scritto in modo atomico;
  3. una sola derivazione PBKDF2 per file, non una per salvataggio;
  4. errori leggibili (non traceback) quando la mappa non si può leggere.
"""
import json
import os
import stat
import sys
from pathlib import Path

import pytest

import pProxy
from pProxy import (
    EncryptionUnavailableError,
    RehydrationEngine,
    SecureMappingStore,
    SensitiveDataDetectionEngine,
    TokenizationEngine,
    main,
)

MAPPA = {"[IBAN_001]": "IT60X0542811101000000123456", "[EMAIL_001]": "a@b.com"}

posix_only = pytest.mark.skipif(os.name != "posix", reason="permessi POSIX")


def _mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


@pytest.fixture
def senza_cryptography(monkeypatch):
    """Simula una macchina su cui il pacchetto ``cryptography`` non è installato."""
    for name in [m for m in sys.modules if m == "cryptography" or m.startswith("cryptography.")]:
        monkeypatch.setitem(sys.modules, name, None)
    monkeypatch.setitem(sys.modules, "cryptography", None)
    monkeypatch.setitem(sys.modules, "cryptography.fernet", None)


@pytest.fixture
def conta_derivazioni(monkeypatch):
    """Conta le derivazioni PBKDF2 effettive, per salt."""
    pytest.importorskip("cryptography")
    chiamate = []
    originale = SecureMappingStore._derive_fernet

    def spia(self, salt):
        chiamate.append(bytes(salt))
        return originale(self, salt)

    monkeypatch.setattr(SecureMappingStore, "_derive_fernet", spia)
    return chiamate


# ── 1. Cifratura fail-closed ─────────────────────────────────────────────────

class TestCifraturaFailClosed:
    def test_senza_cryptography_la_cifratura_richiesta_e_un_errore(
        self, tmp_path, senza_cryptography
    ):
        path = tmp_path / "map.enc"
        with pytest.raises(EncryptionUnavailableError) as exc:
            SecureMappingStore(store_path=str(path), encryption_key="pw")
        assert "cryptography" in str(exc.value)
        assert not path.exists()

    def test_senza_cryptography_nessun_file_in_chiaro(self, tmp_path, senza_cryptography):
        """Il difetto originale: avviso nel log e mappa scritta in chiaro."""
        path = tmp_path / "map.enc"
        try:
            store = SecureMappingStore(store_path=str(path), encryption_key="pw")
            store.store(MAPPA)
        except EncryptionUnavailableError:
            pass
        assert list(tmp_path.iterdir()) == []

    def test_senza_cryptography_la_mappa_in_chiaro_resta_disponibile(
        self, tmp_path, senza_cryptography
    ):
        """Senza passphrase non serve alcuna libreria: il core resta a zero dipendenze."""
        path = tmp_path / "map.json"
        SecureMappingStore(store_path=str(path)).store(MAPPA)
        assert json.loads(path.read_text(encoding="utf-8")) == MAPPA

    def test_cli_si_ferma_invece_di_salvare_in_chiaro(
        self, tmp_path, senza_cryptography, capsys
    ):
        map_file = tmp_path / "mappa.enc"
        code = main([
            "--text", "Scrivi a mario.rossi@example.com", "--anonymize-only", "--no-ner",
            "--provider", "demo", "--encryption-key", "pw", "--save-mapping", str(map_file),
        ])
        captured = capsys.readouterr()
        assert code == 1
        assert "cryptography" in captured.err
        assert not map_file.exists()
        assert "mario.rossi@example.com" not in captured.out

    def test_la_mappa_cifrata_non_contiene_i_valori(self, tmp_path):
        pytest.importorskip("cryptography")
        path = tmp_path / "map.enc"
        SecureMappingStore(store_path=str(path), encryption_key="pw").store(MAPPA)
        raw = path.read_bytes()
        for value in MAPPA.values():
            assert value.encode() not in raw


# ── 2. File privato e scrittura atomica ──────────────────────────────────────

class TestFilePrivatoEAtomico:
    @posix_only
    def test_mappa_in_chiaro_ha_permessi_0600(self, tmp_path):
        path = tmp_path / "map.json"
        SecureMappingStore(store_path=str(path)).store(MAPPA)
        assert _mode(path) == 0o600

    @posix_only
    def test_mappa_cifrata_ha_permessi_0600(self, tmp_path):
        pytest.importorskip("cryptography")
        path = tmp_path / "map.enc"
        SecureMappingStore(store_path=str(path), encryption_key="pw").store(MAPPA)
        assert _mode(path) == 0o600

    @posix_only
    def test_un_file_preesistente_leggibile_da_tutti_viene_ristretto(self, tmp_path):
        path = tmp_path / "map.json"
        path.write_text("{}", encoding="utf-8")
        os.chmod(path, 0o644)
        SecureMappingStore(store_path=str(path)).store(MAPPA)
        assert _mode(path) == 0o600

    @posix_only
    def test_la_umask_non_allarga_i_permessi(self, tmp_path):
        vecchia = os.umask(0)
        try:
            path = tmp_path / "map.json"
            SecureMappingStore(store_path=str(path)).store(MAPPA)
        finally:
            os.umask(vecchia)
        assert _mode(path) == 0o600

    def test_scrittura_interrotta_lascia_intatta_la_versione_precedente(
        self, tmp_path, monkeypatch
    ):
        path = tmp_path / "map.json"
        store = SecureMappingStore(store_path=str(path))
        store.store({"[EMAIL_001]": "prima@example.com"})
        prima = path.read_bytes()

        def rinomina_fallita(src, dst):
            raise OSError("disco pieno")

        monkeypatch.setattr(pProxy.os, "replace", rinomina_fallita)
        with pytest.raises(OSError):
            store.store({"[EMAIL_002]": "dopo@example.com"})

        assert path.read_bytes() == prima
        assert [p.name for p in tmp_path.iterdir()] == ["map.json"], "file temporaneo rimasto"

    def test_nessun_file_temporaneo_dopo_un_salvataggio_riuscito(self, tmp_path):
        path = tmp_path / "map.json"
        store = SecureMappingStore(store_path=str(path))
        for i in range(5):
            store.store({f"[EMAIL_{i:03d}]": f"u{i}@example.com"})
        assert [p.name for p in tmp_path.iterdir()] == ["map.json"]
        assert len(json.loads(path.read_text(encoding="utf-8"))) == 5

    def test_percorso_senza_cartella(self, tmp_path, monkeypatch):
        """Un nome di file nudo ('mappa.json') si salva nella cartella corrente."""
        monkeypatch.chdir(tmp_path)
        SecureMappingStore(store_path="mappa.json").store(MAPPA)
        assert json.loads(Path("mappa.json").read_text(encoding="utf-8")) == MAPPA


# ── 3. Derivazione della chiave ──────────────────────────────────────────────

class TestDerivazioneChiave:
    def test_una_sola_derivazione_per_molti_salvataggi(self, tmp_path, conta_derivazioni):
        store = SecureMappingStore(store_path=str(tmp_path / "m.enc"), encryption_key="pw")
        for i in range(6):
            store.store({f"[EMAIL_{i:03d}]": f"u{i}@example.com"})
        assert len(conta_derivazioni) == 1

    def test_costruire_lo_store_non_deriva_nulla(self, tmp_path, conta_derivazioni):
        SecureMappingStore(store_path=str(tmp_path / "m.enc"), encryption_key="pw")
        assert conta_derivazioni == []

    def test_caricare_e_risalvare_riusa_la_chiave_del_file(self, tmp_path, conta_derivazioni):
        path = tmp_path / "m.enc"
        SecureMappingStore(store_path=str(path), encryption_key="pw").store(MAPPA)
        salt_su_disco = path.read_bytes()[4:20]
        conta_derivazioni.clear()

        store = SecureMappingStore(store_path=str(path), encryption_key="pw")
        store.load()
        store.store({"[CF_001]": "RSSMRA80A01H501U"})
        store.store({"[CF_002]": "VRDLGU85T10F205Z"})

        assert conta_derivazioni == [salt_su_disco]
        assert path.read_bytes()[4:20] == salt_su_disco

        riletto = SecureMappingStore(store_path=str(path), encryption_key="pw")
        riletto.load()
        assert riletto.get_mapping() == {
            **MAPPA, "[CF_001]": "RSSMRA80A01H501U", "[CF_002]": "VRDLGU85T10F205Z",
        }

    def test_passphrase_errata_non_adotta_il_salt_del_file(self, tmp_path):
        pytest.importorskip("cryptography")
        path = tmp_path / "m.enc"
        SecureMappingStore(store_path=str(path), encryption_key="giusta").store(MAPPA)
        store = SecureMappingStore(store_path=str(path), encryption_key="sbagliata")
        with pytest.raises(Exception):
            store.load()
        assert store.get_mapping() == {}
        assert store._salt is None

    def test_file_legacy_passa_al_formato_v2_al_primo_salvataggio(self, tmp_path):
        pytest.importorskip("cryptography")
        import base64
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                         salt=b"privacy_proxy_v1", iterations=480_000)
        key = base64.urlsafe_b64encode(kdf.derive(b"pw"))
        path = tmp_path / "old.enc"
        path.write_bytes(Fernet(key).encrypt(json.dumps({"[CF_001]": "ABC"}).encode()))

        store = SecureMappingStore(store_path=str(path), encryption_key="pw")
        store.load()
        store.store({"[CF_002]": "DEF"})

        raw = path.read_bytes()
        assert raw.startswith(b"PPX2")
        assert raw[4:20] != b"privacy_proxy_v1"
        riletto = SecureMappingStore(store_path=str(path), encryption_key="pw")
        riletto.load()
        assert riletto.get_mapping() == {"[CF_001]": "ABC", "[CF_002]": "DEF"}

    def test_attributo_fernet_resta_disponibile(self, tmp_path):
        pytest.importorskip("cryptography")
        assert SecureMappingStore()._fernet is None
        store = SecureMappingStore(store_path=str(tmp_path / "m.enc"), encryption_key="pw")
        assert store._fernet is not None
        assert store._fernet is store._fernet


# ── 4. Lettura: manomissioni ed errori leggibili ─────────────────────────────

class TestLettura:
    def test_file_manomesso_viene_rifiutato(self, tmp_path):
        pytest.importorskip("cryptography")
        path = tmp_path / "m.enc"
        SecureMappingStore(store_path=str(path), encryption_key="pw").store(MAPPA)
        raw = bytearray(path.read_bytes())
        raw[-10] ^= 0x01
        path.write_bytes(bytes(raw))
        store = SecureMappingStore(store_path=str(path), encryption_key="pw")
        with pytest.raises(Exception):
            store.load()
        assert store.get_mapping() == {}

    def test_file_cifrato_senza_passphrase_spiega_cosa_manca(self, tmp_path):
        pytest.importorskip("cryptography")
        path = tmp_path / "m.enc"
        SecureMappingStore(store_path=str(path), encryption_key="pw").store(MAPPA)
        with pytest.raises(ValueError) as exc:
            SecureMappingStore(store_path=str(path)).load()
        assert "cifrata" in str(exc.value)

    def _salva_cifrata(self, tmp_path):
        path = tmp_path / "m.enc"
        SecureMappingStore(store_path=str(path), encryption_key="giusta").store(
            {"[EMAIL_001]": "mario.rossi@example.com"}
        )
        return path

    def test_cli_ripristino_con_passphrase_giusta(self, tmp_path, capsys):
        pytest.importorskip("cryptography")
        path = self._salva_cifrata(tmp_path)
        code = main(["--rehydrate-from", "Rispondi a [EMAIL_001]",
                     "--load-mapping", str(path), "--encryption-key", "giusta"])
        assert code == 0
        assert "mario.rossi@example.com" in capsys.readouterr().out

    def test_cli_ripristino_con_passphrase_errata_esce_con_errore_leggibile(
        self, tmp_path, capsys
    ):
        pytest.importorskip("cryptography")
        path = self._salva_cifrata(tmp_path)
        code = main(["--rehydrate-from", "Rispondi a [EMAIL_001]",
                     "--load-mapping", str(path), "--encryption-key", "sbagliata"])
        captured = capsys.readouterr()
        assert code == 1
        assert "Impossibile leggere la mappa" in captured.err
        assert "mario.rossi@example.com" not in captured.out + captured.err

    def test_cli_ripristino_di_mappa_cifrata_senza_passphrase(self, tmp_path, capsys):
        pytest.importorskip("cryptography")
        path = self._salva_cifrata(tmp_path)
        code = main(["--rehydrate-from", "Rispondi a [EMAIL_001]", "--load-mapping", str(path)])
        captured = capsys.readouterr()
        assert code == 1
        assert "cifrata" in captured.err

    def test_cli_ripristino_con_mappa_non_json(self, tmp_path, capsys):
        path = tmp_path / "rotta.json"
        path.write_text("{non json", encoding="utf-8")
        code = main(["--rehydrate-from", "ciao [EMAIL_001]", "--load-mapping", str(path)])
        assert code == 1
        assert "Impossibile leggere la mappa" in capsys.readouterr().err


# ── 5. Maiuscole e minuscole nella tokenizzazione (comportamento voluto) ─────

class TestVariantiDiMaiuscole:
    """Lo stesso dato scritto con maiuscole diverse è UNA entità, con UN token.

    È una scelta, non una svista: se "Mario.Rossi@Example.com" e
    "MARIO.ROSSI@EXAMPLE.COM" avessero due token, l'LLM li tratterebbe come due
    destinatari distinti. Il prezzo è che al ripristino tutte le occorrenze
    tornano nella grafia della prima occorrenza nel testo: questi test lo fissano,
    così un cambiamento in un senso o nell'altro è una decisione esplicita.
    """

    TESTO = "Scrivi a Mario.Rossi@Example.com oppure a MARIO.ROSSI@EXAMPLE.COM."

    def _anonimizza(self):
        detector = SensitiveDataDetectionEngine(confidence_threshold=0.7, use_ner=False)
        return TokenizationEngine().tokenize(self.TESTO, detector.detect(self.TESTO))

    def test_le_varianti_condividono_il_token(self):
        anon, mapping = self._anonimizza()
        assert anon.count("[EMAIL_001]") == 2
        assert list(mapping) == ["[EMAIL_001]"]

    def test_il_ripristino_usa_la_grafia_della_prima_occorrenza(self):
        anon, mapping = self._anonimizza()
        assert mapping["[EMAIL_001]"] == "Mario.Rossi@Example.com"
        ripristinato = RehydrationEngine().rehydrate(anon, mapping)
        assert ripristinato == (
            "Scrivi a Mario.Rossi@Example.com oppure a Mario.Rossi@Example.com."
        )

    def test_senza_varianti_il_giro_completo_e_identico(self):
        testo = "Scrivi a mario.rossi@example.com, IBAN IT60X0542811101000000123456."
        detector = SensitiveDataDetectionEngine(confidence_threshold=0.7, use_ner=False)
        anon, mapping = TokenizationEngine().tokenize(testo, detector.detect(testo))
        assert "mario.rossi" not in anon
        assert RehydrationEngine().rehydrate(anon, mapping) == testo
