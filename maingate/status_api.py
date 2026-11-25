#!/usr/bin/env python3
"""MainGate - API de statut imprimante (lecture seule).

Écoute sur 127.0.0.1:9001 (nginx la publie sur le port 82, filtré sur les
IP locales). Interroge Moonraker et renvoie du JSON :

  GET /status      vue organisée (impression, températures, ventilateurs...)
  GET /status/raw  tous les objets Klipper tels que Moonraker les renvoie
  GET /health      vérification interne (ne contacte pas Moonraker)

Seuls des champs documentés de Klipper/Moonraker sont lus. Les valeurs
"calculées" sont indiquées comme telles dans le README.
"""
import http.server
import json
import os
import threading
import time
import urllib.parse
import urllib.request

API_VERSION = "0.3"
MOONRAKER = "http://%s:%s" % (
    os.environ.get("MOONRAKER_HOST", "127.0.0.1"),
    os.environ.get("MOONRAKER_PORT", "7125"),
)
LISTEN = ("127.0.0.1", 9001)
TIMEOUT = 5          # secondes, par requête vers Moonraker
CACHE_TTL = 1.0      # secondes : évite de marteler Moonraker si plusieurs widgets
EXCLUDED_PREFIXES = ("configfile", "gcode_macro")  # volumineux, inutiles ici
SETTINGS_PATH = "/data/settings.json"  # écrit par auth_app.py (page /admin)
NETWORK_PREFIXES = ("eth", "en", "wl")  # interfaces physiques seulement (pas docker/veth)
DASH = "\u2014"

FILE_METADATA_KEYS = (
    "slicer", "slicer_version", "layer_height", "first_layer_height",
    "object_height", "layer_count", "filament_total", "filament_weight_total",
    "filament_name", "filament_type", "nozzle_diameter", "estimated_time",
    "first_layer_extr_temp", "first_layer_bed_temp",
)

_cache = {}
_cache_lock = threading.Lock()
_meta = {"name": None, "data": None}


def moonraker_get(path):
    req = urllib.request.Request(MOONRAKER + path, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode("utf-8"))


def try_get(path):
    """Renvoie le champ "result" de Moonraker, ou None en cas d'échec."""
    try:
        return moonraker_get(path).get("result")
    except Exception:
        return None


def cached(key, fn):
    with _cache_lock:
        entry = _cache.get(key)
        if entry and time.time() - entry[0] < CACHE_TTL:
            return entry[1]
    value = fn()
    with _cache_lock:
        _cache[key] = (time.time(), value)
    return value


def rnd(value, digits=2):
    return round(value, digits) if isinstance(value, (int, float)) else value


def read_price():
    """Prix du filament en $/kg (réglé dans /admin), ou None s'il n'est pas défini."""
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            value = json.load(f).get("price_per_kg")
    except Exception:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def fmt_duration(seconds):
    if seconds is None:
        return DASH
    seconds = int(round(seconds))
    hours, rest = divmod(seconds, 3600)
    minutes = rest // 60
    return "%d h %02d min" % (hours, minutes) if hours else "%d min" % minutes


def temp_text(entry):
    if not entry or entry.get("temperature") is None:
        return DASH
    text = "%.1f" % entry["temperature"]
    if entry.get("target") is not None:
        text += " / %.0f" % entry["target"]
    return text + " \u00b0C"


def estimate_layer(state, z, first_height, layer_height, layer_count):
    """Couche actuelle estimée d'après la hauteur Z (approximatif : z-hop, vase mode...)."""
    if state not in ("printing", "paused"):
        return None
    if None in (z, first_height, layer_height, layer_count) or layer_height <= 0:
        return None
    layer = 1 + int(round((z - first_height) / layer_height)) if z > first_height else 1
    return max(1, min(int(layer_count), layer))


def trim_host(host):
    """Garde le dernier relevé Moonraker et les interfaces réseau physiques."""
    if not isinstance(host, dict):
        return host
    out = {k: host[k] for k in (
        "cpu_temp", "system_cpu_usage", "system_memory", "system_uptime",
        "throttled_state", "websocket_connections") if k in host}
    stats = host.get("moonraker_stats")
    if isinstance(stats, list) and stats:
        out["moonraker_stats"] = stats[-1]
    elif isinstance(stats, dict):
        out["moonraker_stats"] = stats
    network = host.get("network")
    if isinstance(network, dict):
        out["network"] = {k: v for k, v in network.items() if k.startswith(NETWORK_PREFIXES)}
    return out


def query_objects():
    listing = try_get("/printer/objects/list")
    if not listing:
        return None
    names = [n for n in listing.get("objects", []) if not n.startswith(EXCLUDED_PREFIXES)]
    if not names:
        return {}
    query = "&".join(urllib.parse.quote(n, safe="") for n in names)
    result = try_get("/printer/objects/query?" + query)
    return (result or {}).get("status")


def file_metadata(filename):
    if not filename:
        return None
    if _meta["name"] == filename and _meta["data"]:
        return _meta["data"]
    data = try_get("/server/files/metadata?filename=" + urllib.parse.quote(filename, safe="/"))
    if data:
        _meta["name"], _meta["data"] = filename, data
    return data


def build_status():
    now = time.time()
    server = try_get("/server/info")
    pinfo = try_get("/printer/info")
    objs = query_objects()
    out = {
        "api_version": API_VERSION,
        "timestamp": now,
        "moonraker_reachable": bool(server or pinfo or objs is not None),
    }
    if not out["moonraker_reachable"]:
        return out

    server = server or {}
    pinfo = pinfo or {}
    out["klippy"] = {
        "state": pinfo.get("state"),
        "state_message": pinfo.get("state_message"),
        "hostname": pinfo.get("hostname"),
        "software_version": pinfo.get("software_version"),
        "connected": server.get("klippy_connected"),
        "moonraker_version": server.get("moonraker_version"),
    }
    if objs is None:
        return out

    ps = objs.get("print_stats", {})
    vs = objs.get("virtual_sdcard", {})
    ds = objs.get("display_status", {})
    filename = ps.get("filename") or ""
    meta = file_metadata(filename) or {}

    elapsed = ps.get("print_duration")
    progress = vs.get("progress")
    remaining = None
    if elapsed is not None and progress and progress > 0:
        remaining = max(0.0, elapsed / progress - elapsed)          # calculé
    est = meta.get("estimated_time")
    remaining_slicer = None
    if est is not None and elapsed is not None:
        remaining_slicer = max(0.0, est - elapsed)                  # calculé
    used = ps.get("filament_used")
    total_fil = meta.get("filament_total")
    layers = ps.get("info") or {}

    weight_total = meta.get("filament_weight_total")
    weight_used = None
    if weight_total is not None and used is not None and total_fil:
        weight_used = weight_total * used / total_fil                # calculé
    price = read_price()
    cost_used = weight_used / 1000.0 * price if (weight_used is not None and price is not None) else None
    cost_total = weight_total / 1000.0 * price if (weight_total is not None and price is not None) else None

    gpos = (objs.get("gcode_move") or {}).get("gcode_position")
    z = gpos[2] if isinstance(gpos, list) and len(gpos) > 2 else None
    layer_estimated = estimate_layer(
        ps.get("state"), z, meta.get("first_layer_height"),
        meta.get("layer_height"), meta.get("layer_count"))

    out["print"] = {
        "state": ps.get("state"),
        "message": ps.get("message"),
        "filename": filename or None,
        "is_active": vs.get("is_active"),
        "progress_percent": rnd(progress * 100) if progress is not None else None,
        "progress_display_percent": rnd(ds["progress"] * 100) if ds.get("progress") is not None else None,
        "display_message": ds.get("message"),
        "file_position": vs.get("file_position"),
        "file_size": vs.get("file_size"),
        "elapsed_s": rnd(elapsed),
        "total_duration_s": rnd(ps.get("total_duration")),
        "time_remaining_s": rnd(remaining),
        "time_remaining_slicer_s": rnd(remaining_slicer),
        "eta_epoch": rnd(now + remaining) if remaining is not None else None,
        "filament_used_mm": rnd(used),
        "filament_used_m": rnd(used / 1000.0) if used is not None else None,
        "filament_estimated_total_mm": total_fil,
        "filament_estimated_remaining_mm": rnd(max(0.0, total_fil - used)) if (total_fil is not None and used is not None) else None,
        "time_remaining_min": rnd(remaining / 60.0, 1) if remaining is not None else None,
        "current_layer": layers.get("current_layer"),
        "total_layer": layers.get("total_layer"),
        "current_layer_estimated": layer_estimated,
        "total_layer_estimated": meta.get("layer_count"),
        "filament_used_g_estimated": rnd(weight_used),
        "price_per_kg": price,
        "cost_used": rnd(cost_used),
        "cost_total_estimated": rnd(cost_total),
        "file": {k: meta[k] for k in FILE_METADATA_KEYS if meta.get(k) is not None},
    }

    temps, fans, sensors = {}, {}, {}
    for name, obj in objs.items():
        if not isinstance(obj, dict):
            continue
        if obj.get("temperature") is not None:
            temps[name] = {
                k: rnd(obj[k]) for k in
                ("temperature", "target", "power", "speed", "measured_min_temp", "measured_max_temp")
                if k in obj
            }
        elif "temperature" not in obj and "speed" in obj and name != "gcode_move":
            fans[name] = {k: rnd(obj[k], 3) for k in ("speed", "rpm") if k in obj}
        if name.startswith(("filament_switch_sensor", "filament_motion_sensor")):
            sensors[name] = {k: obj.get(k) for k in ("filament_detected", "enabled")}
    out["temperatures"] = temps
    out["fans"] = fans
    out["filament_sensors"] = sensors

    for key in ("toolhead", "gcode_move", "motion_report", "idle_timeout", "system_stats"):
        if key in objs:
            out[key] = objs[key]

    host = try_get("/machine/proc_stats")
    if host is not None:
        out["host"] = trim_host(host)
    totals = try_get("/server/history/totals")
    if totals is not None:
        out["history_totals"] = totals.get("job_totals")

    pr = out["print"]
    layer_now = layers.get("current_layer") if layers.get("current_layer") is not None else layer_estimated
    layer_all = layers.get("total_layer") if layers.get("total_layer") is not None else meta.get("layer_count")
    out["display"] = {
        "progress": "%.1f %%" % pr["progress_percent"] if pr["progress_percent"] is not None else DASH,
        "elapsed": fmt_duration(elapsed),
        "remaining": fmt_duration(remaining),
        "layer": "%s/%s" % (layer_now, layer_all) if (layer_now is not None and layer_all is not None) else DASH,
        "extruder": temp_text(temps.get("extruder")),
        "bed": temp_text(temps.get("heater_bed")),
        "filament": "%.2f m" % pr["filament_used_m"] if pr["filament_used_m"] is not None else DASH,
        "weight": "%.1f g" % weight_used if weight_used is not None else DASH,
        "cost": "%.2f $" % cost_used if cost_used is not None else DASH,
    }
    return out


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "MainGateStatus"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass  # nginx journalise déjà chaque requête

    def _send(self, code, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path.rstrip("/") or "/"
        if path == "/health":
            return self._send(200, {"ok": True})
        if path in ("/", "/status"):
            data = cached("status", build_status)
            return self._send(200 if data.get("moonraker_reachable") else 503, data)
        if path == "/status/raw":
            objs = cached("raw", query_objects)
            if objs is None:
                return self._send(503, {"error": "moonraker_unreachable"})
            return self._send(200, objs)
        return self._send(404, {"error": "not_found"})


if __name__ == "__main__":
    server = http.server.ThreadingHTTPServer(LISTEN, Handler)
    server.daemon_threads = True
    server.serve_forever()
