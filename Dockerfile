<<<<<<< HEAD
# 1. Image pinnée avec un hash SHA256 précis
FROM python:3.11.4-slim@sha256:0b23cfb7425d065008b778022a17b1551c82f8b4866ee5a7a200084b7e2eafbf

# 2. Création d'un utilisateur non-root
RUN useradd -m appuser
=======
# EXPERT Dockerfile (intentionally imperfect)
FROM python:3.11-slim

>>>>>>> fa5f7a0 (Setup local repo for project)
WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && update-ca-certificates \
 && rm -rf /var/lib/apt/lists/*

<<<<<<< HEAD
# Le .dockerignore filtrera automatiquement les secrets
=======
# Still copies too much (students should add .dockerignore)
>>>>>>> fa5f7a0 (Setup local repo for project)
COPY . /app

RUN pip install --no-cache-dir -r web/requirements.txt && \
    pip install --no-cache-dir -r vault/requirements.txt

<<<<<<< HEAD
# 3. On bascule sur l'utilisateur restreint
USER appuser
EXPOSE 5000 7000

CMD ["python","web/app.py"]
=======
# Still runs as root (students should fix with USER)
EXPOSE 5000 7000

CMD ["python","web/app.py"]
>>>>>>> fa5f7a0 (Setup local repo for project)
