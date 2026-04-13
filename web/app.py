import os
import re
import json
import requests
from requests.exceptions import RequestException
from flask import Flask, request, jsonify, abort, make_response, render_template_string

# === [BlueTeam] AJOUTS MINIMAUX (SSRF) ===
import socket                     # [BT] pour résoudre le DNS
import ipaddress                  # [BT] pour tester IP privées/loopback/etc.
from urllib.parse import urlsplit # [BT] pour parser l’URL + hostname/port

app = Flask(__name__)

# still intentionally flawed for the exercise
app.config["SECRET_KEY"] = os.getenv("JWT_SECRET", "dev-secret-CHANGE-ME")
app.config["JSON_SORT_KEYS"] = False

HOME = """
<h1>Mission Pipeline</h1>
<p>Objectif : sécuriser <b>la supply chain</b> (build/test/scan), les <b>secrets</b>, et l'app (<b>SSRF</b>, auth, logs).</p>
<ul>
  <li><a href="/status">/status</a></li>
  <li><a href="/whoami">/whoami</a></li>
  <li><a href="/fetch?url=https://example.com">/fetch</a> (⚠️ SSRF)</li>
  <li><a href="/admin?token=...">/admin</a> (token)</li>
  <li><a href="/docs">/docs</a> (pistes DevSecOps)</li>
</ul>
<p><b>Note</b> : tout reste local. Les “flags” sont dans les variables d’environnement.</p>
"""

@app.get("/")
def index():
    return render_template_string(HOME)

@app.get("/status")
def status():
    return jsonify({"service": "escape-app-expert", "ok": True})

# Weak identity: trusts a header set by reverse proxy (not present here)
@app.get("/whoami")
def whoami():
    user = request.headers.get("X-User", "anonymous")
    resp = make_response(jsonify({"user": user}))
    # intentionally weak cookie settings for workshop
    resp.set_cookie("session", "dev", httponly=False, samesite="Lax")
    return resp

# SSRF: fetch arbitrary URL from server side
# Pedagogical angle: should implement allowlist + block internal ranges + DNS rebinding protection


# === [BlueTeam] AJOUTS MINIMAUX (SSRF) ===
# Objectif : interdire l’accès à 'vault' depuis /fetch + bloquer IP privées/loopback/etc. :contentReference[oaicite:4]{index=4}
BLOCKED_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "vault", "web"}  # [BT] hostnames internes
BLOCKED_SUFFIXES = (".local", ".internal", ".docker", ".lan")                 # [BT] suffixes internes
MAX_REDIRECTS = 3                                                            # [BT] redirections contrôlées

def _is_forbidden_ip(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return (
        a.is_private
        or a.is_loopback
        or a.is_link_local
        or a.is_multicast
        or a.is_reserved
        or a.is_unspecified
    )

def _resolve_all(host: str, port: int) -> set[str]:
    ips = set()
    for family, _type, _proto, _canon, sockaddr in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
        # sockaddr[0] contient l’IP (IPv4 ou IPv6)
        ips.add(sockaddr[0])
    return ips

def _validate_url(raw_url: str) -> tuple[bool, str]:
    """
    [BT] Validation SSRF :
      - autorise uniquement http/https
      - bloque hostnames internes (vault, localhost…)
      - résout le DNS et bloque si IP privée/loopback/etc.
    """
    try:
        u = urlsplit(raw_url)
    except Exception:
        return False, "Invalid URL"

    if u.scheme not in ("http", "https"):
        return False, "Only http/https URLs are allowed"

    if not u.hostname:
        return False, "URL must include a hostname"

    host = u.hostname.strip().lower()
    if host in BLOCKED_HOSTS or any(host.endswith(s) for s in BLOCKED_SUFFIXES):
        return False, "Hostname is not allowed"

    port = u.port or (443 if u.scheme == "https" else 80)

    # Cas IP littérale
    try:
        ipaddress.ip_address(host)
        if _is_forbidden_ip(host):
            return False, "IP address is not allowed"
        return True, "OK"
    except ValueError:
        pass

    # Cas hostname -> DNS -> blocage IP privées/loopback/etc.
    try:
        ips = _resolve_all(host, port)
    except socket.gaierror:
        return False, "Hostname could not be resolved"

    if any(_is_forbidden_ip(ip) for ip in ips):
        return False, "Destination is not allowed"

    return True, "OK"

def _safe_get_with_redirects(start_url: str):
    """
    [BT] Redirections contrôlées :
      - pas de allow_redirects automatique
      - validation de chaque hop
    """
    url = start_url
    for _ in range(MAX_REDIRECTS + 1):
        ok, reason = _validate_url(url)
        if not ok:
            return None, (403, reason)

        try:
            r = requests.get(url, timeout=2, allow_redirects=False)
        except RequestException:
            # [BT] suppression de la fuite "details": str(e) côté client :contentReference[oaicite:5]{index=5}
            return None, (502, "Upstream request failed")

        # Gérer manuellement les redirections (301/302/303/307/308)
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location", "")
            if not loc:
                return None, (502, "Upstream redirect without Location")
            url = requests.compat.urljoin(url, loc)
            continue

        return r, None

    return None, (502, "Too many redirects")


@app.get("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "Missing url parameter"}), 400

    if url.startswith("file://"):
        return jsonify({"error": "file:// URLs are not allowed"}), 400

    # === [BlueTeam] AJOUT: blocage SSRF (vault / IP privées / hostnames internes) ===
    r, err = _safe_get_with_redirects(url)
    if err is not None:
        status, reason = err
        if status == 403:
            return jsonify({"error": "Blocked outbound request", "reason": reason}), 403
        return jsonify({"error": reason}), status

    return (
        r.text,
        r.status_code,
        {"Content-Type": r.headers.get("Content-Type", "text/plain")},
    )

# Admin protected by static token (still bad)
@app.get("/admin")
def admin():
    token = request.args.get("token", "")
    if token != os.getenv("ADMIN_TOKEN", ""):
        abort(403)
    return jsonify({
        "admin": True,
        "flag_supply_chain": os.getenv("FLAG_SUPPLY", "FLAG{missing}"),
        "hint": "Try auditing the pipeline scripts & dependencies. Also check internal services.",
    })

@app.get("/docs")
def docs():
    return render_template_string("""
<h2>DevSecOps targets (expert)</h2>
<ol>
  <li>Supply chain: tests + SAST + dependency audit + image scan + SBOM + signing</li>
  <li>Secrets hygiene: no .env committed, no tokens in repo, add secret scanning</li>
  <li>AppSec: SSRF mitigation, auth hardening, safer cookies, logging</li>
  <li>Build hardening: pin base image, non-root user, .dockerignore, minimal image</li>
</ol>
<p>Tip: there is an internal service on the Docker network you should not be able to read from the web app.</p>
""")

if __name__ == "__main__":
    # === [BlueTeam] MODIF: éviter debug=True en environnement container (réduit fuites 500) :contentReference[oaicite:6]{index=6} ===
    app.run(host="0.0.0.0", port=5000, debug=False)
