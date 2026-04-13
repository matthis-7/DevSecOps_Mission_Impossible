# Image de base (pinnée)
FROM python:3.11.4-slim

# Dossier de travail
WORKDIR /app

# Copier les dépendances
COPY web/requirements.txt .

# Installer les dépendances
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code
COPY web/ .

# Exposer le port
EXPOSE 5000

# Lancer l'application
CMD ["python", "app.py"]