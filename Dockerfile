# Immagine minimale per la web app pProxy.
# Il core non ha dipendenze esterne obbligatorie: si installano solo quelle web.
# Build:  docker build -t pproxy-web .
# Run:    docker run --rm -p 8000:8000 pproxy-web
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Dipendenze web (FastAPI, uvicorn, multipart, httpx)
COPY requirements-web.txt ./
RUN pip install --no-cache-dir -r requirements-web.txt

# Codice: motore + alias + package web (i test e i prompt non servono in immagine)
COPY pProxy.py privacy_proxy.py ./
COPY webapp ./webapp

# Esecuzione come utente non privilegiato
RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8000

# Avvio del server ASGI
CMD ["uvicorn", "webapp.app:app", "--host", "0.0.0.0", "--port", "8000"]
