
# DevSecOps Escape Game ## “Supply Chain Guardian”

Objectif : aller **au-delà** des failles évidentes et travailler **DevSecOps** : supply chain, scans, politique, preuve, remediation.

---

## Prérequis

- Docker Desktop
- Git + VS Code
- (optionnel) Trivy, pip-audit, gitleaks (ou équivalents)

---

## Démarrage

```bash
docker compose up --build
```

Ouvrir :

- <http://localhost:5001>

---

## Gameplay (2 phases)

### Phase Red (attaque / preuve)

Vous devez trouver **au moins 2 flags** et démontrer **2 risques supply chain**.

### Phase Blue (défense / durcissement)

Vous devez rendre :

- une app corrigée (SSRF + cookies + auth)
- un build durci (Dockerfile + .dockerignore + non-root)
- une CI améliorée (tests + scans + quality gates)
- une stratégie secrets (gitleaks + .env.example + rotation)

---

## Missions Red Team (expert)

### M1 — SSRF vers service interne (30 pts) Trouver un moyen de lire un contenu d’un service **non exposé** au host

Indice : un service interne existe sur le réseau Docker, et l’app fait des requêtes serveur.

**Flag attendu :** `FLAG{ssrf_reached_vault}`

<<<<<<< HEAD
Solution:
http://localhost:5001/fetch?url=http://vault:7000/debug

=======
>>>>>>> fa5f7a0 (Setup local repo for project)
---

### M2 — Weak admin auth (15 pts)

Accéder à `/admin` et récupérer `FLAG{supply_chain_guardian}`.

Piste : d’où vient le token ? (secrets, env, fichiers, logs, build context)

<<<<<<< HEAD
Solution :
docker exec -it devsecops_mission_impossible-web-1 cat .env -> se trouve le tocken admin puis
http://vault:7000/secret?token=bSXdxNlOVFk8tEPgmqRWNwOibH6wxJVx

=======
>>>>>>> fa5f7a0 (Setup local repo for project)
---

### M3 — Supply chain risks (25 pts)

Identifier **5 risques** dans la CI / pipeline :

- tags `latest`
- pas de tests
- pas de SAST
- pas d’audit dépendances
- pas de scan d’image
- pas de SBOM
- pas de signature
- pas de policy gate
- pas de provenance

Livrer une liste structurée risque → impact → mitigation.
<<<<<<< HEAD
1. Utilisation du tag latest pour l'image Docker

Risque : Le pipeline build l'image avec docker build -t mycorp/escape-app:latest ..

Impact : Le tag latest est mutable. Si une mise à jour corrompue ou instable est poussée sur l'image de base, votre build cassera de manière imprévisible ou déploiera une version compromise sans que vous ne changiez une ligne de code.

Mitigation : Pinner une version spécifique (ex: python:3.11.4-slim) ou utiliser le hash SHA256 exact de l'image (Image Pinning).

2. Absence d'audit des dépendances (SCA)

Risque : L'étape 3 du pipeline (Dependency audit) est ignorée. L'application utilise des versions fixes de Flask et Requests.

Impact : Si une faille critique (CVE) est découverte dans ces bibliothèques, l'application restera vulnérable. Les attaquants exploitent souvent les composants tiers.

Mitigation : Intégrer un outil comme pip-audit dans la CI pour vérifier les failles connues des packages Python et bloquer le build en cas de faille critique.

3. Absence de test de sécurité statique (SAST)

Risque : Le code n'est pas analysé avant d'être packagé (l'étape "Lint?" est ignorée).

Impact : Des vulnérabilités évidentes (comme votre faille SSRF dans app.py) sont directement poussées en production alors qu'elles auraient pu être détectées par une analyse de code automatisée.

Mitigation : Ajouter un outil de SAST comme bandit (spécifique à Python) dans le pipeline pour scanner le code source.

4. Absence de scan d'image (Container Scanning)

Risque : L'étape 5 (Image scan) est "skipped".

Impact : L'image de base (python:3.11-slim) ou les paquets installés via apt-get peuvent contenir des vulnérabilités au niveau de l'OS.

Mitigation : Utiliser un scanner comme trivy sur l'image Docker finale avant de l'envoyer dans un registre.

5. Manque de traçabilité et d'intégrité (Pas de SBOM ni de Signature)

Risque : Les étapes 6 et 7 (SBOM et Signing) n'existent pas.

Impact : Il est impossible de savoir exactement ce qui tourne dans le conteneur en cas d'audit de sécurité, et rien ne garantit que l'image téléchargée par le serveur de production est bien celle construite par votre CI.

Mitigation : Générer un SBOM avec syft pour lister tous les composants, et signer l'image cryptographiquement avec cosign.
=======

>>>>>>> fa5f7a0 (Setup local repo for project)
---

### M4 — Build context leakage (15 pts)Prouver qu’un fichier “qui ne devrait pas” se retrouve dans l’image

Piste : `.dockerignore`

---
<<<<<<< HEAD
Pas de ficjer .dockerignore donc tout les fichiers sont executés. A l'éxécution de la commande ls -la /app, 
drwxr-xr-x 1 root root 4096 Feb 20 07:52 .
drwxr-xr-x 1 root root 4096 Feb 20 07:53 ..
-rw-r--r-- 1 root root 6148 Feb 20 07:45 .DS_Store
drwxr-xr-x 2 root root 4096 Feb 20 07:43 .dist
-rw-rw-rw- 1 root root  321 Feb 19 14:24 .env
-rw-rw-rw- 1 root root  111 Feb 19 14:24 .env.example
drwxrwxrwx 3 root root 4096 Feb 19 14:24 .github
-rw-rw-rw- 1 root root  521 Feb 19 15:40 Dockerfile
-rw-rw-rw- 1 root root 3061 Feb 19 23:40 README.md
-rw-rw-rw- 1 root root  709 Feb 19 14:45 docker-compose.yml
drwxrwxrwx 2 root root 4096 Feb 19 14:24 scripts
drwxrwxrwx 2 root root 4096 Feb 19 14:24 vault
drwxrwxrwx 2 root root 4096 Feb 19 14:24 web

Et du coup le .env se balade ici.
=======

>>>>>>> fa5f7a0 (Setup local repo for project)
## Missions Blue Team

### B1 — Mitiger SSRF proprement (35 pts)

Mettre en place :

- allowlist de domaines OU
- blocage des IP privées/loopback + vérif DNS (anti rebinding) + redirections contrôlées

But : interdire l’accès à `vault` depuis `/fetch`.

---

### B2 — Pipeline avec Quality Gates (35 pts)

Ajouter (au choix) :

- tests (même simples)
- `pip-audit` (ou équivalent)
- `bandit` (SAST python) (ou équivalent)
- scan image `trivy` (ou équivalent)
- SBOM (syft) (ou équivalent)
- signature (cosign) (ou équivalent)

Condition : si un scan échoue → le pipeline échoue.

---

### B3 — Secrets hygiene (20 pts)

- supprimer `.env` du repo (remplacer par `.env.example`)
- supprimer tout fichier “secrets”
- ajouter secret scanning (gitleaks ou pre-commit)
- documenter la rotation

---

### B4 — Docker hardening (20 pts)

- base image pin
- `USER` non-root
- `HEALTHCHECK`
- `.dockerignore`
- réduire la surface (option multi-stage)

---

## Présentation finale (6 minutes / équipe)

1. Les 2 flags trouvés + preuve
2. Les 5 risques supply chain + impact
3. Les correctifs majeurs (SSRF + CI + secrets)
4. La checklist DevSecOps (10 règles d’or)

---

## Important

Les attaques doivent rester inoffensives.
