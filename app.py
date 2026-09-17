"""NetScope — local network scanner. Flask backend."""
from __future__ import annotations
import threading
import time

from flask import Flask, jsonify, render_template

from backend import discovery, network

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/network")
def api_network():
    iface = network.get_primary()
    return jsonify({
        "success": True,
        "interface": iface,
        "local_name": network.local_hostname(),
    })


@app.route("/api/devices")
def api_devices():
    s = discovery.get_state()
    return jsonify({
        "success": True,
        "scanning": s["scanning"],
        "stage": s["stage"],
        "progress": s["progress"],
        "last_scan": s["last_scan"],
        "error": s["error"],
        "iface": s["iface"],
        "local_name": s["local_name"],
        "devices": s["devices"],
    })


@app.route("/api/scan", methods=["POST"])
def api_scan():
    started = discovery.start_scan()
    if not started:
        return jsonify({"success": False, "message": "A scan is already running."}), 409
    return jsonify({"success": True})


@app.route("/api/scan/status")
def api_scan_status():
    s = discovery.get_state()
    return jsonify({
        "success": True,
        "scanning": s["scanning"],
        "stage": s["stage"],
        "progress": s["progress"],
        "last_scan": s["last_scan"],
        "error": s["error"],
    })


def _auto_scan():
    time.sleep(0.6)
    try:
        discovery.start_scan()
    except Exception:
        pass


if __name__ == "__main__":
    threading.Thread(target=_auto_scan, daemon=True).start()
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)