"""NetScope — local network scanner. Flask backend."""
from __future__ import annotations
import logging
import threading
import time

from flask import Flask, jsonify, render_template

from backend import discovery, hostname as hostname_mod, network

# Route Python logging to stdout so you see it in the terminal
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
)

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
        "mdns_stats": s["mdns_stats"],
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
        "mdns_stats": s["mdns_stats"],
    })


@app.route("/api/debug")
def api_debug():
    """Shows what the resolver saw, per source."""
    return jsonify({
        "success": True,
        "mdns_passive_stats": hostname_mod.passive_stats(),
        "passive_cache": hostname_mod.get_passive(),
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