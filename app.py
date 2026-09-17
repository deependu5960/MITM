"""NetScope — Flask app. Scanner + MITM lab module."""
from __future__ import annotations
import json
import logging
import threading
import time

from flask import Flask, Response, jsonify, render_template, request

from backend import discovery, network
from backend.mitm.manager import get_manager
from backend.mitm.stream import STREAM
from config import CONFIG

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("app")

app = Flask(__name__)


# ==========================================================================
# HTML
# ==========================================================================
@app.route("/")
def index():
    return render_template("index.html")


# ==========================================================================
# Scanner API (unchanged)
# ==========================================================================
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
    })


@app.route("/api/debug")
def api_debug():
    from backend import hostname as hostname_mod
    return jsonify({
        "success": True,
        "mdns_passive_stats": hostname_mod.passive_stats(),
        "passive_cache": hostname_mod.get_passive(),
    })


# ==========================================================================
# MITM API
# ==========================================================================
@app.route("/api/mitm/status")
def mitm_status():
    return jsonify({"success": True, **get_manager().get_status()})


@app.route("/api/mitm/start", methods=["POST"])
def mitm_start():
    body = request.get_json(silent=True) or {}
    victim_ip = (body.get("ip") or "").strip()
    iface = body.get("iface") or None
    confirm = body.get("confirm") is True

    if not victim_ip:
        return jsonify({"success": False, "error": "Missing victim IP"}), 400

    if CONFIG.REQUIRE_CONFIRMATION and not confirm:
        return jsonify({
            "success": False,
            "error": "Confirmation required",
        }), 400

    # Lab boundary check
    if CONFIG.LAB_SUBNETS:
        import ipaddress
        ok = False
        for cidr in CONFIG.LAB_SUBNETS:
            try:
                if ipaddress.ip_address(victim_ip) in ipaddress.ip_network(cidr, strict=False):
                    ok = True
                    break
            except ValueError:
                continue
        if not ok:
            return jsonify({
                "success": False,
                "error": f"Target {victim_ip} is outside the configured lab subnets",
            }), 403

    # Scanner must know the device
    device = discovery.find_device(victim_ip)
    if not device:
        return jsonify({
            "success": False,
            "error": f"Device {victim_ip} not found in the last scan. Scan first.",
        }), 404

    result = get_manager().start(victim_ip, iface=iface)
    if not result.get("ok"):
        return jsonify({"success": False, "error": result.get("error", "Unknown error")}), 500
    return jsonify({"success": True, "session": result["session"]})


@app.route("/api/mitm/stop", methods=["POST"])
def mitm_stop():
    return jsonify({"success": True, **get_manager().stop()})


@app.route("/api/mitm/pause", methods=["POST"])
def mitm_pause():
    return jsonify({"success": True, **get_manager().pause()})


@app.route("/api/mitm/resume", methods=["POST"])
def mitm_resume():
    return jsonify({"success": True, **get_manager().resume()})


@app.route("/api/mitm/clear", methods=["POST"])
def mitm_clear():
    return jsonify({"success": True, **get_manager().clear_packets()})


@app.route("/api/mitm/packets")
def mitm_packets():
    """Recent packets (used as fallback if SSE is unavailable)."""
    limit = int(request.args.get("limit", "500"))
    recent = STREAM.recent(limit=limit)
    return jsonify({
        "success": True,
        "packets": [r.to_dict() for r in recent],
        "paused": STREAM.is_paused(),
    })


@app.route("/api/mitm/stream")
def mitm_stream():
    """Server-Sent Events stream of packet records."""
    resp = Response(STREAM.sse_stream(), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-cache"
    resp.headers["X-Accel-Buffering"] = "no"
    resp.headers["Connection"] = "keep-alive"
    return resp

@app.route("/api/mitm/flows")
def mitm_flows():
    return jsonify({
        "success": True,
        "flows": get_manager().get_flows(),
    })


# ==========================================================================
# Boot
# ==========================================================================
def _auto_scan():
    time.sleep(0.6)
    try:
        discovery.start_scan()
    except Exception:
        pass


if __name__ == "__main__":
    threading.Thread(target=_auto_scan, daemon=True).start()
    app.run(host=CONFIG.HOST, port=CONFIG.PORT, debug=CONFIG.DEBUG, threaded=True)