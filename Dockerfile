# 1. Image pinnée avec un hash SHA256 précis
FROM python:3.11.4-slim@sha256:0b23cfb7425d065008b778022a17b1551c82f8b4866ee5a7a200084b7e2eafbf

# 2. Création d'un utilisateur non-root
RUN useradd -m appuser
WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && update-ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Le .dockerignore filtrera automatiquement les secrets
COPY . /app

RUN pip install --no-cache-dir -r web/requirements.txt && \
    pip install --no-cache-dir -r vault/requirements.txt

# 3. On bascule sur l'utilisateur restreint
USER appuser
EXPOSE 5000

CMD ["python","web/app.py"]