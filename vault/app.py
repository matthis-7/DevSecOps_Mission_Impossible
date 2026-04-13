import os
from flask import Flask, request, jsonify, abort

app = Flask(__name__)

@app.get("/secret")
def secret():
    tok = request.args.get("token", "")
    if tok != os.getenv("VAULT_TOKEN", ""):
        abort(403)
    return jsonify({
        "vault": "ok",
        "flag_vault": os.getenv("FLAG_VAULT", "FLAG{missing}")
    })

@app.get("/health")
def health():
    return jsonify({"ok": True})

@app.get("/debug")
def debug():
    # === [BlueTeam] MODIF: ne plus exposer os.environ (fuite majeure de secrets)  ===
    # Debug désactivé par défaut : renvoie 404 (comme si la route n'existait pas)
    if os.getenv("VAULT_DEBUG", "false").lower() != "true":
        abort(404)

    # Si le debug est volontairement activé, il est protégé par un token dédié
    dbg_tok = request.args.get("token", "")
    if dbg_tok != os.getenv("VAULT_DEBUG_TOKEN", ""):
        abort(403)

    # Liste blanche : aucun secret / aucune variable d'environnement
    return jsonify({"service": "vault", "debug": True})

if __name__ == "__main__":
    # === [BlueTeam] MODIF: éviter debug=True (réduit fuites 500) :contentReference[oaicite:12]{index=12} ===
    app.run(host="0.0.0.0", port=7000, debug=False)
