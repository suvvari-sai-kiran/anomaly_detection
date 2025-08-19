import os
from flask import Flask, jsonify, request, send_from_directory
from dotenv import load_dotenv
import mysql_logger
import switch_blocker

load_dotenv()

app = Flask(__name__, static_folder="static_ui", static_url_path="")

# -------- API Endpoints --------

@app.get("/flows")
@app.get("/api/records")
def flows():
    limit = int(request.args.get("limit", 100))
    return jsonify(mysql_logger.fetch_latest(limit=limit))

@app.get("/blocked")
@app.get("/api/blocked")
def blocked():
    return jsonify(mysql_logger.fetch_blocked())

@app.post("/block/<ip>")
@app.post("/api/block")
def block(ip=None):
    if not ip:
        ip = (request.get_json(silent=True) or {}).get("ip")
    if not ip:
        return jsonify({"ok": False, "error": "Missing IP"}), 400
    try:
        msg = switch_blocker.block_ip(ip)
        mysql_logger.insert_blocked_ip(ip, device=os.getenv("SWITCH_HOST"), reason=msg)
        return jsonify({"ok": True, "message": msg})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.post("/unblock/<ip>")
@app.post("/api/unblock")
def unblock(ip=None):
    if not ip:
        ip = (request.get_json(silent=True) or {}).get("ip")
    if not ip:
        return jsonify({"ok": False, "error": "Missing IP"}), 400
    try:
        msg = switch_blocker.unblock_ip(ip)
        mysql_logger.unblock_ip(ip)
        return jsonify({"ok": True, "message": msg})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# -------- Dashboard --------

@app.get("/")
def index():
    return send_from_directory("static_ui", "index.html")

# -------- Static assets --------

@app.get("/<path:path>")
def static_proxy(path):
    return send_from_directory("static_ui", path)

if __name__ == "__main__":
    port = int(os.getenv("API_PORT", "5001"))
    print(f"[INFO] API server on http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port)
