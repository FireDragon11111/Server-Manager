# File: update_node_server_host.py
"""
Update Node Server Host
-----------------------
Provides the /updates/ endpoints for uploading, listing, and downloading update
packages.  Supports HEAD requests on /updates/<filename> so clients can read
Last‑Modified, and a local‑only shutdown endpoint for graceful in‑process
termination.  Files older than 48 h are moved to backups with a timestamp so
they never overwrite.  Every action is logged to the event logger.
"""

import os
import sys
import re
import threading
import time
import shutil
from datetime import datetime
from flask import (
    Flask, request, jsonify, send_from_directory,
    make_response, abort
)
from werkzeug.http import http_date
from utils import log_event

app = Flask(__name__)

if getattr(sys, "frozen", False):
    APP_ROOT = os.path.dirname(sys.executable)
else:
    APP_ROOT = os.path.dirname(os.path.abspath(__file__))

STORAGE_DIR   = os.path.join(APP_ROOT, "update_node_storage")
UPLOAD_FOLDER = os.path.join(STORAGE_DIR, "updates")
BACKUP_FOLDER = os.path.join(STORAGE_DIR, "backups")
PULL_REQUESTS_FOLDER = os.path.join(STORAGE_DIR, "pull_requests")
os.makedirs(PULL_REQUESTS_FOLDER, exist_ok=True)
NODE_REGISTRY = {}
os.makedirs(STORAGE_DIR, exist_ok=True)

for d in (UPLOAD_FOLDER, BACKUP_FOLDER):
    os.makedirs(d, exist_ok=True)
    log_event("Self", "Init", f"Ensured directory exists: {d}")

log_event("Self", "Init", f"Booting Update‑Node server; APP_ROOT={APP_ROOT}")

@app.route('/pull_request', methods=['POST'])
def pull_request():
    data = request.json
    server = data.get("server")
    requested_by = data.get("requested_by", "unknown")
    if not server:
        return jsonify(error="Missing server name."), 400
    ts = datetime.utcnow().strftime('%Y%m%d%H%M%S%f')
    pr_file = os.path.join(PULL_REQUESTS_FOLDER, f"{server}_PULL_{ts}.req")
    with open(pr_file, 'w', encoding='utf-8') as f:
        f.write(f"requested_by={requested_by}\n")
        f.write(f"timestamp={ts}\n")
    log_event("Nodes", "Pull", f"Pull-request beacon created for {server} by {requested_by}")
    return jsonify(result="ok", pull_request=pr_file)

@app.route('/pending_pull', methods=['GET'])
def pending_pull():
    server = request.args.get("server")
    if not server:
        return jsonify(error="Missing server name."), 400
    matches = [f for f in os.listdir(PULL_REQUESTS_FOLDER)
               if f.startswith(f"{server}_PULL_")]

    if not matches:
        return jsonify(pull_request=False), 404

    matches.sort()
    beacon = matches[-1]
    path   = os.path.join(PULL_REQUESTS_FOLDER, beacon)
    m = re.search(r"_PULL_(\d+)\.req$", beacon)
    ts = m.group(1) if m else ""

    with open(path, 'r', encoding='utf-8') as f:
        details = f.read()

    os.remove(path)
    log_event("Nodes", "Pull", f"Pending-pull beacon {beacon} consumed for {server}")

    return jsonify(
        pull_request=True,
        timestamp=ts,
        details=details
    ), 200

@app.route('/pull_requests_list')
def pull_requests_list():
    files = os.listdir(PULL_REQUESTS_FOLDER)
    return jsonify(files=files)

def schedule_48h_cleanup(poll_interval=3600):
    log_event("Self", "Cleanup", "Starting 48 h cleanup thread")
    def _run():
        while True:
            now = time.time()
            log_event("Self", "Cleanup", "48 h cleanup tick")
            for fn in os.listdir(UPLOAD_FOLDER):
                src = os.path.join(UPLOAD_FOLDER, fn)
                if os.path.isfile(src):
                    age = now - os.path.getmtime(src)
                    if age > 48 * 3600:
                        name, ext = os.path.splitext(fn)
                        ts = time.strftime("%Y%m%d%H%M%S")
                        dest_name = f"{name}_{ts}{ext}"
                        dest = os.path.join(BACKUP_FOLDER, dest_name)
                        try:
                            shutil.copy2(src, dest)
                            os.remove(src)
                            log_event("Self", "Cleanup", f"Auto‑archived {fn} (age {age}s) → {dest_name}")
                        except Exception as e:
                            log_event("Self", "Cleanup", f"48 h cleanup failed for {fn}: {e}", "error")
            time.sleep(poll_interval)
    threading.Thread(target=_run, daemon=True).start()

schedule_48h_cleanup()

@app.before_request
def log_request_info():
    log_event(
        "Self", "Request",
        f"Incoming {request.method} {request.path} from {request.remote_addr}; "
        f"args={dict(request.args)}; files={list(request.files.keys())}"
    )

@app.after_request
def log_response_info(response):
    log_event(
        "Self", "Response",
        f"Response: {request.method} {request.path} → {response.status_code}"
    )
    return response

@app.route('/updates/', defaults={'filename': None}, methods=['GET', 'POST'])
@app.route('/updates/<path:filename>',               methods=['GET', 'HEAD'])
def updates(filename):
    log_event("Nodes", "Updates", f"/updates/ handler; method={request.method}; filename={filename}")
    if request.method == 'POST' and filename is None:
        if 'file' not in request.files:
            log_event("Nodes", "Updates", "POST /updates/ missing 'file' part", "warning")
            return jsonify(error="No file part"), 400
        f = request.files['file']
        if not f.filename:
            log_event("Nodes", "Updates", "POST /updates/ empty filename", "warning")
            return jsonify(error="No file selected"), 400
        dest = os.path.join(UPLOAD_FOLDER, f.filename)
        try:
            f.save(dest)
            log_event("Nodes", "Updates", f"Uploaded file saved: {dest}")
            return jsonify(message=f"Uploaded {f.filename}"), 201
        except Exception as e:
            log_event("Nodes", "Updates", f"Failed to save {dest}: {e}", "error")
            return jsonify(error=str(e)), 500
    if request.method == 'HEAD' and filename:
        src = os.path.join(UPLOAD_FOLDER, filename)
        if not os.path.exists(src):
            log_event("Nodes", "Updates", f"HEAD /updates/{filename} not found", "warning")
            return abort(404)
        stat = os.stat(src)
        resp = make_response('', 200)
        resp.headers['Last-Modified']  = http_date(stat.st_mtime)
        resp.headers['Content-Length'] = stat.st_size
        log_event("Nodes", "Updates", f"HEAD /updates/{filename}: LM={resp.headers['Last-Modified']}, Size={stat.st_size}")
        return resp
    if request.method == 'GET' and filename:
        src = os.path.join(UPLOAD_FOLDER, filename)
        if not os.path.exists(src):
            log_event("Nodes", "Updates", f"GET /updates/{filename} not found", "warning")
            return jsonify(error="File not found"), 404
        log_event("Nodes", "Updates", f"GET /updates/{filename}: serving file")
        return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)
    if request.method == 'GET' and filename is None:
        files  = os.listdir(UPLOAD_FOLDER)
        server = request.args.get('server')
        log_event("Nodes", "Updates", f"Listing updates; server filter={server}; files={files}")
        if server:
            if server == "Server Manager":
                files = [f for f in files if f == "Server Manager.exe"]
            else:
                files = [f for f in files if f.startswith(f"{server}_") and f.endswith(".zip")]
            log_event("Nodes", "Updates", f"Filtered files: {files}")
        return jsonify(files=files), 200

    log_event("Nodes", "Updates", f"Method not allowed: {request.method} filename={filename}", "error")
    return abort(405)

@app.route('/register', methods=['POST'])
def register_node():
    data = request.json
    if not data:
        log_event("Nodes", "Registry", "Register endpoint: missing JSON body.", "warning")
        return jsonify(error="Missing JSON body"), 400

    ip = data.get("ip") or request.remote_addr
    hostname = data.get("hostname")
    servers = data.get("servers", [])
    ssl_enabled = bool(data.get("ssl_enabled", False))

    log_event("Nodes", "Registry", f"Registering node: ip={ip}, hostname={hostname}, servers={servers}, ssl={ssl_enabled}")

    ts = time.time()
    for srv in servers:
        NODE_REGISTRY[srv] = dict(
            ip=ip,
            hostname=hostname,
            ssl_enabled=ssl_enabled,
            last_seen=ts
        )

    return jsonify(result="ok", registered_servers=servers)

@app.route('/whois_server_owner')
def whois_server_owner():
    server = request.args.get('server')
    meta = NODE_REGISTRY.get(server)
    if not meta:
        return jsonify(error="No owner registered for server."), 404

    return jsonify(
        ip=meta["ip"],
        hostname=meta.get("hostname"),
        ssl_enabled=meta.get("ssl_enabled"),
        last_seen=meta.get("last_seen")
    )

def schedule_registry_cleanup(interval_seconds=3600, expiry_seconds=86400):
    def cleanup():
        while True:
            now = time.time()
            expired = []
            for srv, meta in list(NODE_REGISTRY.items()):
                if now - meta.get("last_seen", 0) > expiry_seconds:
                    expired.append((srv, meta))
            for srv, meta in expired:
                log_event(
                    "Nodes", "Registry",
                    f"Server '{srv}' (node {meta.get('ip')}/{meta.get('hostname')}) has not checked in for over 24 hours. Removing from registry.",
                    "warning"
                )
                del NODE_REGISTRY[srv]
            time.sleep(interval_seconds)
    threading.Thread(target=cleanup, daemon=True).start()

@app.route('/__shutdown', methods=['POST'])
def shutdown():
    log_event("Self", "Shutdown", "Shutdown endpoint called", "info")
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        log_event("Self", "Shutdown", "werkzeug.server.shutdown missing; os._exit", "warning")
        os._exit(0)
    func()
    log_event("Self", "Shutdown", "Shutdown function invoked")
    return jsonify(message="Shutdown initiated"), 200

schedule_registry_cleanup(interval_seconds=3600, expiry_seconds=86400)

@app.route('/booted', methods=['POST'])
def node_booted():
    data = request.json
    ip = data.get("ip") or request.remote_addr
    hostname = data.get("hostname", "")
    servers = data.get("servers", [])
    just_updated = data.get("just_updated", False)
    ts = data.get("timestamp") or datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    boot_log_path = os.path.join(STORAGE_DIR, "booted.log")
    msg = f"[{ts}] Node booted: ip={ip}, hostname={hostname}, just_updated={just_updated}, servers={servers}"
    try:
        with open(boot_log_path, 'a', encoding='utf-8') as f:
            f.write(msg + "\n")
    except Exception as e:
        log_event("Self", "Booted", f"Failed to write to booted.log: {e}", "error")
    log_event("Self", "Booted", msg)
    for srv in servers:
        if srv in NODE_REGISTRY:
            NODE_REGISTRY[srv]['last_boot'] = ts

    return jsonify(status="ok", message="Node boot event recorded.")

@app.route('/booted_events')
def booted_events():
    boot_log_path = os.path.join(STORAGE_DIR, "booted.log")
    try:
        with open(boot_log_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        return "<br>".join(line.strip() for line in lines), 200
    except Exception as e:
        return f"Error reading booted.log: {e}", 500

if __name__ == "__main__":
    log_event("Self", "Init", "Starting Update‑Node server on port 5001…")
    from waitress import serve
    serve(app, host="0.0.0.0", port=5001)
