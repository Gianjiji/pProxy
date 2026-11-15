"""Coerenza dei file di packaging con ciò che il repository contiene davvero.

Guardie economiche contro due rotture già viste: un Dockerfile che copia file
inesistenti (la build fallisce al primo COPY) e un requirements.txt in cui le
dipendenze "opzionali" risultano attive (un `pip install -r` scarica gigabyte di
modelli NER a chi voleva solo eseguire i test).
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _righe_attive(nome: str):
    righe = (ROOT / nome).read_text(encoding="utf-8").splitlines()
    return [r.strip() for r in righe if r.strip() and not r.strip().startswith("#")]


def _pacchetto(riga: str) -> str:
    return re.split(r"[<>=!~\[; ]", riga, maxsplit=1)[0].lower()


def test_dockerfile_copia_solo_file_esistenti():
    sorgenti = []
    for riga in (ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines():
        parti = riga.split()
        if parti and parti[0] == "COPY" and not any(p.startswith("--from") for p in parti):
            sorgenti.extend(parti[1:-1])
    assert sorgenti, "nessuna istruzione COPY trovata"
    mancanti = [s for s in sorgenti if not (ROOT / s).exists()]
    assert mancanti == [], f"il Dockerfile copia file inesistenti: {mancanti}"


def test_dockerfile_installa_un_requirements_esistente():
    testo = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    for nome in re.findall(r"pip install[^\n]*-r\s+(\S+)", testo):
        assert (ROOT / nome).is_file(), f"{nome} citato nel Dockerfile ma assente"


def test_requirements_base_installa_solo_gli_strumenti_di_test():
    """Il core non ha dipendenze: tutto il resto deve restare commentato."""
    assert {_pacchetto(r) for r in _righe_attive("requirements.txt")} == {"pytest", "pytest-cov"}


def test_requirements_web_copre_gli_import_della_web_app():
    pacchetti = {_pacchetto(r) for r in _righe_attive("requirements-web.txt")}
    assert {"fastapi", "uvicorn", "python-multipart"} <= pacchetti


def test_nessuna_riga_di_requirements_inizia_con_uno_spazio():
    """Uno spazio al posto del '#' rende attiva una dipendenza che sembra commentata."""
    for nome in ("requirements.txt", "requirements-web.txt"):
        for n, riga in enumerate((ROOT / nome).read_text(encoding="utf-8").splitlines(), 1):
            assert not (riga[:1].isspace() and riga.strip()), f"{nome}:{n} inizia con uno spazio"
