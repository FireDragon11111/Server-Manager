"""
File: server_manager/update_and_receive.py
"""

import os
import sys
import zipfile
import shutil
import requests
import time
import re
import ctypes
import traceback
import io
import socket
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
import subprocess
import urllib.parse
import base64
import email.utils
from urllib.parse import quote
from base64_variables import UPDATER_HELPER_B64
from utils import get_root_dir, get_app_root, log_event, get_config_value, CONFIG_PATH

if getattr(sys, "frozen", False):
    _app_root = os.path.dirname(sys.executable)
else:
    _module_dir = os.path.dirname(os.path.abspath(__file__))
    _app_root = os.path.abspath(os.path.join(_module_dir, os.pardir))

_receive_root = os.path.join(_app_root, "update_node_receive_storage")
os.makedirs(_receive_root, exist_ok=True)

UPDATE_NODE_URL = get_config_value(CONFIG_PATH, "update_node_url", "https://update-node.firecrafting.net")
UPDATE_NODE_LOCAL_URL = get_config_value(CONFIG_PATH, "update_node_local_url", "http://127.0.0.1:5001")

def log_audit(message: str, level: str = "info", server_name: str | None = None):
    category = "Nodes"
    subcat   = server_name if server_name else "UpdateNodeServer"
    log_event(category, subcat, message, level)

def notify_booted(servers, just_updated: bool = False):
    payload = {
        "ip": UpdateAndReceive.get_my_ip()
              if hasattr(UpdateAndReceive, "get_my_ip")
              else _get_local_ip(),
        "hostname": socket.gethostname(),
        "servers": servers,
        "just_updated": just_updated,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    def _post(url: str):
        return requests.post(url, json=payload, timeout=10)

    try:
        resp = _post(f"{UPDATE_NODE_URL}/booted")          # ← fixed
    except Exception as e_remote:
        log_audit(f"[BootNotify] Public POST failed ({e_remote}); "
                  f"trying local …", "warning")
        try:
            resp = _post(f"{UPDATE_NODE_LOCAL_URL}/booted")  # ← fixed
        except Exception as e_local:
            log_audit(f"[BootNotify] Local POST also failed ({e_local}). "
                      f"Payload={payload}", "error")
            return
    log_audit(f"[BootNotify] Sent booted event. Status={resp.status_code}. "
              f"Payload={payload}")

def _get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def extract_updater_helper(dest_path: str) -> bool:
    try:
        binary_data = base64.b64decode(UPDATER_HELPER_B64)
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        with open(dest_path, "wb") as f:
            f.write(binary_data)
        log_event("Self", "Update", f"Updater helper extracted → {dest_path}")
        return True
    except Exception as e:
        log_event("Self", "Update", f"Error extracting updater helper: {e}",
                  "error")
        return False

def launch_updater_helper(current_exe: str,
                          new_exe_backup: str,
                          backups_folder: str):
    exe_dir = os.path.dirname(current_exe)
    helper  = os.path.join(exe_dir, "updater_helper.exe")

    if not os.path.exists(helper):
        log_event("Self", "Update", "Updater helper missing – extracting …",
                  "warning")
        if not extract_updater_helper(helper):
            log_event("Self", "Update",
                      "Failed to extract updater helper, aborting", "error")
            return

    args = f'"{current_exe}" "{new_exe_backup}" "{backups_folder}"'
    log_event("Self", "Update",
              f"Launching updater helper with args: {args}")

    creation_flags = (
        subprocess.CREATE_NEW_PROCESS_GROUP |
        subprocess.DETACHED_PROCESS |
        getattr(subprocess, "CREATE_NO_WINDOW", 0)
    )

    try:
        subprocess.Popen([helper, current_exe, new_exe_backup, backups_folder],
                         cwd=exe_dir,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL,
                         creationflags=creation_flags)
        log_event("Self", "Update", "Updater helper launched successfully")
    except Exception as e:
        log_event("Self", "Update",
                  f"Failed to launch updater helper: {e}", "error")

    time.sleep(1)
    os._exit(0)

def _get_update_node_base(gui):
    try:
        if getattr(gui, "update_mode_var", None) and gui.update_mode_var.get():
            return UPDATE_NODE_LOCAL_URL
    except Exception:
        pass
    return UPDATE_NODE_URL

def _updates_endpoint(gui):
    return f"{_get_update_node_base(gui)}/updates"

def get_peer_update_node_base(server_name: str) -> str | None:
    try:
        rel_path = f"/whois_server_owner?server={quote(server_name)}"
        resp     = _call_remote_then_local(rel_path, "get")

        if not resp.ok:
            log_audit(f"[PeerQuery] {server_name}: registry returned {resp.status_code} {resp.text}")
            return None

        data = resp.json()
        ip        = data.get("ip")
        hostname  = data.get("hostname")
        ssl_flag  = bool(data.get("ssl_enabled", False))

        host      = hostname or ip
        if not host:
            log_audit(f"[PeerQuery] {server_name}: no host/ip in registry data {data}")
            return None

        scheme    = "https" if ssl_flag else "http"
        base_url  = f"{scheme}://{host}:5001"

        log_audit(f"[PeerQuery] {server_name}: resolved owner → {base_url}")
        return base_url

    except Exception as e:
        log_audit(f"[PeerQuery] {server_name}: exception {e}")
        return None

def _call_remote_then_local(path, method="get", **kwargs):
    remote = f"{UPDATE_NODE_URL}{path}"
    local  = f"{UPDATE_NODE_LOCAL_URL}{path}"
    try:
        return getattr(requests, method)(remote, timeout=10, **kwargs)
    except Exception as e_remote:
        try:
            return getattr(requests, method)(local, timeout=5, **kwargs)
        except Exception:
            raise e_remote

class UpdateAndReceive:
    def __init__(self, gui):
        self.gui = gui
        self.update_folder          = os.path.join(_receive_root, "updates")
        self.backup_folder          = os.path.join(_receive_root, "backups")
        self.pending_updates_folder = os.path.join(_receive_root, "pending_updates")
        self.self_updates_folder    = os.path.join(_receive_root, "self_updates")
        for d in (self.update_folder,
                  self.backup_folder,
                  self.pending_updates_folder,
                  self.self_updates_folder):
            os.makedirs(d, exist_ok=True)
        self.update_handlers: dict[str, UpdateHandler] = {}
        self.server_meta:    dict[str, dict]           = {}
        log_audit("[Init] UpdateAndReceive logging started")

    def finish_init(self):
        self.schedule_daily_updates()
        self.periodic_register_with_update_node()
        
    def periodic_register_with_update_node(self, interval=3600):
        def _register_loop():
            while True:
                self.register_with_update_node()
                time.sleep(interval)
        threading.Thread(target=_register_loop, daemon=True).start()

    def _log_audit(self, message: str):
        log_event("Nodes", "UpdateNodeServer", message)

    def add_server(self, server_name: str, *, ssl_enabled: bool) -> None:
        if server_name in self.update_handlers:
            return

        handler = UpdateHandler(
            gui=self.gui,
            server_name=server_name,
            update_folder=self.update_folder,
            backup_folder=self.backup_folder,
            pending_folder=self.pending_updates_folder,
        )
        self.update_handlers[server_name] = handler
        self.server_meta[server_name] = {"ssl": bool(ssl_enabled)}
        handler.start()
        if ssl_enabled:
            try:
                self.register_with_update_node()
            except Exception as e:
                log_audit(f"[add_server] re-register failed: {e}")

    def remove_server(self, server_name):
        if server_name in self.update_handlers:
            self.update_handlers[server_name].stop()
            del self.update_handlers[server_name]

    def schedule_daily_updates(self):
        def run():
            while True:
                now = time.localtime()
                seconds_until_midnight = ((24 - now.tm_hour - 1) * 3600 +
                                         (60 - now.tm_min  - 1) * 60 +
                                         (60 - now.tm_sec))
                time.sleep(seconds_until_midnight)
                for h in self.update_handlers.values():
                    h.download_latest_update()
                time.sleep(60)
        threading.Thread(target=run, daemon=True).start()
        
    def register_with_update_node(self) -> None:
        import socket, threading
        ssl_only = sorted(
            name for name, meta in self.server_meta.items() if meta.get("ssl")
        )
        payload = {
            "ip":          self.get_my_ip(),
            "hostname":    socket.gethostname(),
            "servers":     ssl_only,
            "ssl_enabled": True,
        }

        def _post(url: str) -> requests.Response:
            log_audit(f"[Register] → POST {url} | payload={payload}")
            return requests.post(url, json=payload, timeout=10)

        try:
            r_local = _post(f"{UPDATE_NODE_LOCAL_URL}/register")   # ← fixed
            if r_local.ok:
                log_audit(f"[Register] ✓ node registered via local "
                          f"(status {r_local.status_code})")
            else:
                log_audit(f"[Register] ✗ local registry rejected "
                          f"({r_local.status_code}): {r_local.text}")
        except Exception as e_loc:
            log_audit(f"[Register] local POST failed ({e_loc})")

        def _public():
            try:
                r_pub = _post(f"{UPDATE_NODE_URL}/register")       # ← fixed
                if r_pub.ok:
                    log_audit(f"[Register] ✓ node registered via public "
                              f"(status {r_pub.status_code})")
                else:
                    log_audit(f"[Register] ✗ public registry rejected "
                              f"({r_pub.status_code}): {r_pub.text}")
            except Exception as e_pub:
                log_audit(f"[Register] public POST failed ({e_pub})")

        threading.Thread(target=_public, daemon=True).start()

    @staticmethod
    def get_my_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"
        finally:
            s.close()

def delete_file_with_retries(path: str,
                             retries: int = 3,
                             delay: float = 1.5) -> bool:
    for attempt in range(1, retries + 1):
        try:
            os.remove(path)
            log_event("Nodes", "UpdateNodeServer",
                      f"[Cleanup] Deleted {path} on attempt {attempt}")
            return True
        except Exception as e:
            log_event("Nodes", "UpdateNodeServer",
                      f"[Cleanup] attempt {attempt}/{retries} – "
                      f"could not delete {path}: {e}", "warning")
            time.sleep(delay)

    log_event("Nodes", "UpdateNodeServer",
              f"[Cleanup] ERROR – failed to delete {path} "
              f"after {retries} attempts", "error")
    return False

class UpdateHandler:
    ZIP_RX = re.compile(r"_(\d{14})\.zip$")
    PULL_RX  = re.compile(r"_PULL_(\d{14})\.req$")

    def __init__(self, gui, server_name, update_folder, backup_folder, pending_folder):
        self.gui            = gui
        self.server_name    = server_name
        self.update_folder  = update_folder
        self.backup_folder  = backup_folder
        self.pending_folder = pending_folder
        self.last_handled_pull_ts = None
        self.stop_event   = threading.Event()
        self.poll_thread  = threading.Thread(target=self._poll, daemon=True)
        self.watch_thread = threading.Thread(target=self._watch, daemon=True)

    def start(self) -> None:
        self.poll_thread.start()
        self.watch_thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.poll_thread.join()
        self.watch_thread.join()

    def pull_current_files(self) -> None:
        audit = self.gui.update_and_receive._log_audit
        base  = _get_update_node_base(self.gui)
        url   = f"{base}/pull_request"
        ts = time.strftime("%Y%m%d%H%M%S")
        payload = {
            "server":       self.server_name,
            "requested_by": socket.gethostname(),
            "timestamp":    ts,
        }

        audit(f"[{self.server_name}] 🚩 sending pull-request beacon → {url} | {payload}")

        try:
            r = requests.post(url, json=payload, timeout=15)
            r.raise_for_status()
            audit(f"[{self.server_name}] ✅ pull-request beacon accepted ({r.status_code})")
            self.safe_log(f"[{self.server_name}] Pull-request queued on Update-Node")
        except Exception as e:
            # Fallback to local URL if remote fails
            local_url = f"{UPDATE_NODE_LOCAL_URL}/pull_request"
            audit(f"[{self.server_name}] ❌ pull-request to remote failed: {e}")
            audit(f"[{self.server_name}] Retrying with local: {local_url}")
            try:
                r = requests.post(local_url, json=payload, timeout=10)
                r.raise_for_status()
                audit(f"[{self.server_name}] ✅ pull-request beacon accepted locally ({r.status_code})")
                self.safe_log(f"[{self.server_name}] Pull-request queued on local Update-Node")
            except Exception as le:
                audit(f"[{self.server_name}] ❌ pull-request beacon FAILED locally: {le}")
                self.safe_log(f"[{self.server_name}] Pull-request failed: {le}")
                return
        time.sleep(10)
        self.fetch_updates()

    def _check_for_pull_requests(self):
        if getattr(self.gui, "update_mode_var", None) and self.gui.update_mode_var.get():
            return

        base     = _updates_endpoint(self.gui)
        list_url = f"{base}/?server={urllib.parse.quote(self.server_name)}"
        audit    = self.gui.update_and_receive._log_audit
        audit(f"[{self.server_name}] 🔍 pull-check GET {list_url}")

        try:
            resp  = requests.get(list_url, timeout=10)
            resp.raise_for_status()
            files = resp.json().get("files", [])
        except Exception as e:
            ip = _get_local_ip()
            audit(f"[IP: {ip}] [{self.server_name}] Remote check failed "
                  f"({e}); falling back to local node.")
            try:
                local_url = (
                    f"{UPDATE_NODE_LOCAL_URL}/updates/?server="
                    + urllib.parse.quote(self.server_name)           # ← fixed
                )
                audit(f"[{self.server_name}] Fallback GET {local_url}")
                resp  = requests.get(local_url, timeout=5)
                resp.raise_for_status()
                files = resp.json().get("files", [])
            except Exception as le:
                audit(f"[{self.server_name}] Local fallback failed: {le}")
                files = []

        newest = None
        for fn in files:
            m = self.PULL_RX.search(fn)
            if m and fn.startswith(f"{self.server_name}_"):
                ts = m.group(1)
                if newest is None or ts > newest:
                    newest = ts

        if newest and (self.last_handled_pull_ts is None or newest > self.last_handled_pull_ts):
            self.last_handled_pull_ts = newest
            self.safe_log(f"[{self.server_name}] ⇢ received pull-request {newest} – packaging now")
            self.package_and_send()

    def safe_log(self, msg: str, category: str = "Update"):
        log_event("Nodes", self.server_name, msg)
        try:
            self.gui.log_message(msg, category)
        except Exception:
            pass

    def check_for_pending_pull(self):
        if getattr(self.gui, "update_mode_var", None) and self.gui.update_mode_var.get():
            return

        audit = self.gui.update_and_receive._log_audit
        url   = f"{_get_update_node_base(self.gui)}/pending_pull?server={quote(self.server_name)}"
        audit(f"[{self.server_name}] 🔍 pending-pull GET {url}")

        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 404:
                return
            r.raise_for_status()

            data      = r.json()
            ts        = data.get("timestamp") or ""
            details   = data.get("details", "").strip()
            if ts and (self.last_handled_pull_ts is None or ts > self.last_handled_pull_ts):
                self.last_handled_pull_ts = ts
                self.safe_log(f"[{self.server_name}] 📡 Pull-request beacon {ts} received — packaging now.")
                if details:
                    audit(f"[{self.server_name}] Beacon details: {details}")
                self.package_and_send()
            else:
                audit(f"[{self.server_name}] No newer pull-request beacon")

        except Exception as e:
            audit(f"[{self.server_name}] Remote pending_pull failed: {e}")
            # Fallback to local
            local_url = f"{UPDATE_NODE_LOCAL_URL}/pending_pull?server={quote(self.server_name)}"
            audit(f"[{self.server_name}] Retrying pending_pull with local: {local_url}")
            try:
                r = requests.get(local_url, timeout=5)
                if r.status_code == 404:
                    return
                r.raise_for_status()

                data      = r.json()
                ts        = data.get("timestamp") or ""
                details   = data.get("details", "").strip()
                if ts and (self.last_handled_pull_ts is None or ts > self.last_handled_pull_ts):
                    self.last_handled_pull_ts = ts
                    self.safe_log(f"[{self.server_name}] 📡 Pull-request beacon {ts} received — packaging now.")
                    if details:
                        audit(f"[{self.server_name}] Beacon details: {details}")
                    self.package_and_send()
                else:
                    audit(f"[{self.server_name}] No newer pull-request beacon (local)")
            except Exception as le:
                self.safe_log(f"[{self.server_name}] Error polling pending_pull (local): {le}")

    def _poll(self, interval: int = 300):
        while not self.stop_event.is_set():
            try:
                self._check_for_pull_requests()
                self.check_for_pending_pull()
                self.fetch_updates()
            except Exception as e:
                self.safe_log(f"[{self.server_name}] poll-loop error: {e}")
                self.safe_log(traceback.format_exc())
            time.sleep(interval)

    def fetch_updates(self):
        mgr   = self.gui.update_and_receive
        audit = mgr._log_audit

        audit(f"[{self.server_name}] 🔍 fetch_updates")
        try:
            fn = self._get_latest()
        except Exception as e:
            audit(f"[{self.server_name}] ERROR during _get_latest: {e}")
            return

        if not fn:
            audit(f"[{self.server_name}] No candidate update found")
            return

        if not self._is_update_newer(fn):
            audit(f"[{self.server_name}] Candidate {fn} not newer → skipping")
            return

        audit(f"[{self.server_name}] Newer update available: {fn}")
        audit(f"[{self.server_name}] Attempting download of {fn}")
        try:
            ok = self.download(fn)
        except Exception as e:
            audit(f"[{self.server_name}] ERROR during download: {e}")
            return

        pending_path = os.path.join(self.pending_folder, fn)
        if ok and os.path.isfile(pending_path):
            audit(f"[{self.server_name}] ✅ Download succeeded → {pending_path}")
        else:
            audit(f"[{self.server_name}] ❌ Download failed for {fn}")

    def download(self, filename: str) -> bool:
        mgr   = self.gui.update_and_receive
        audit = mgr._log_audit
        primary = _updates_endpoint(self.gui)
        remote_url  = f"{primary}/{filename}"
        dst  = os.path.join(self.pending_folder, filename)
        audit(f"[{self.server_name}] Downloading {filename} from {remote_url}")
        try:
            r = requests.get(remote_url, stream=True, timeout=120)
            r.raise_for_status()
            with open(dst, "wb") as fp:
                for chunk in r.iter_content(1024):
                    fp.write(chunk)
            audit(f"[{self.server_name}] ✅ Downloaded → {dst}")
            return True
        except Exception as e:
            audit(f"[{self.server_name}] ⚠️ Public download failed: {e}")
        local_base = UPDATE_NODE_LOCAL_URL
        local_url = f"{local_base}/updates/{filename}"
        audit(f"[{self.server_name}] Retrying download from local: {local_url}")
        try:
            r = requests.get(local_url, stream=True, timeout=120)
            r.raise_for_status()
            with open(dst, "wb") as fp:
                for chunk in r.iter_content(1024):
                    fp.write(chunk)
            audit(f"[{self.server_name}] ✅ Downloaded from local → {dst}")
            return True
        except Exception as e2:
            audit(f"[{self.server_name}] ❌ Local download failed: {e2}")
            return False

    def _get_latest(self):
        mgr   = self.gui.update_and_receive
        audit = mgr._log_audit
        base       = _updates_endpoint(self.gui)
        timeout_s  = 10
        list_url   = f"{base}/?server={urllib.parse.quote(self.server_name)}"
        audit(f"[{self.server_name}] GET {list_url} (timeout={timeout_s}s)")
        files: list[str] = []
        try:
            r = requests.get(list_url, timeout=timeout_s)
            r.raise_for_status()
            files = r.json().get("files", [])
        except requests.exceptions.RequestException as e:
            audit(f"[{self.server_name}] Remote lookup failed: {e}")
            try:
                local_url = (
                    f"{UPDATE_NODE_LOCAL_URL}/updates/?server="
                    + urllib.parse.quote(self.server_name)
                )
                audit(f"[{self.server_name}] Fallback GET {local_url}")
                r = requests.get(local_url, timeout=5)
                r.raise_for_status()
                files = r.json().get("files", [])
            except requests.exceptions.RequestException as le:
                audit(f"[{self.server_name}] Local fallback failed: {le}")
                return None
        except Exception as e:
            audit(f"[{self.server_name}] Unexpected error in _get_latest: {e}")
            return None
        if not files:
            audit(f"[{self.server_name}] files list empty")
            return None
        audit(f"[{self.server_name}] files: {files}")
        newest_fn = None
        newest_ts = None
        for fname in files:
            m = self.ZIP_RX.search(fname)
            if m and fname.startswith(self.server_name + "_"):
                ts = m.group(1)
                if newest_ts is None or ts > newest_ts:
                    newest_ts, newest_fn = ts, fname

        if newest_fn:
            audit(f"[{self.server_name}] Selected {newest_fn}")
        return newest_fn

    def _is_update_newer(self, update_filename):
        m = self.ZIP_RX.search(update_filename)
        if not m:
            self.safe_log(f"[{self.server_name}] Cannot parse timestamp from {update_filename} – assuming newer")
            return True
        try:
            update_ts = time.mktime(time.strptime(m.group(1), "%Y%m%d%H%M%S"))
        except Exception as e:
            self.safe_log(f"[{self.server_name}] Timestamp parse error: {e} – assuming newer")
            return True

        srv_dir = os.path.join(get_root_dir(), self.server_name)
        if not os.path.isdir(srv_dir):
            self.safe_log(f"[{self.server_name}] Server dir missing – update considered newer")
            return True

        latest_mtime = 0
        for root, _, files in os.walk(srv_dir):
            for f in files:
                try:
                    latest_mtime = max(latest_mtime, os.path.getmtime(os.path.join(root, f)))
                except Exception:
                    pass

        self.safe_log(f"[{self.server_name}] compare: update_ts={update_ts}, local_latest={latest_mtime}")
        return update_ts > latest_mtime

    def _watch(self):
        class H(FileSystemEventHandler):
            def __init__(self, parent): self.parent = parent
            def on_created(self, ev):
                if (not ev.is_directory
                    and ev.src_path.endswith(".zip")
                    and os.path.basename(ev.src_path).startswith(self.parent.server_name + "_")):
                    try:
                        self.parent.safe_log(f"[{self.parent.server_name}] _watch saw {ev.src_path}")
                        self.parent.apply(ev.src_path)
                    except Exception as e:
                        self.parent.safe_log(f"[{self.parent.server_name}] CRITICAL: apply() in watch failed: {e}")
                        self.parent.safe_log(traceback.format_exc())

        obs = Observer()
        obs.schedule(H(self), self.pending_folder, recursive=False)
        obs.start()
        while not self.stop_event.is_set():
            time.sleep(1)
        obs.stop()
        obs.join()

    @staticmethod
    def log_extraction_summary(server_name, zip_files, zip_dirs, copied_files, copied_dirs, logger):
        logger(f"[{server_name}] -------- Extraction Summary --------")
        logger(f"[{server_name}] ZIP      → {zip_files} file(s), {zip_dirs} folder(s)")
        logger(f"[{server_name}] Extracted → {copied_files} file(s), {copied_dirs} folder(s)")
        delta_files = copied_files - zip_files
        delta_dirs  = copied_dirs - zip_dirs
        if delta_files == 0 and delta_dirs == 0:
            logger(f"[{server_name}] ✅ All items match exactly")
        else:
            if delta_files < 0:
                logger(f"[{server_name}] ⚠ {abs(delta_files)} fewer files extracted")
            elif delta_files > 0:
                logger(f"[{server_name}] ⚠ {delta_files} extra files extracted")
            if delta_dirs < 0:
                logger(f"[{server_name}] ⚠ {abs(delta_dirs)} fewer folders extracted")
            elif delta_dirs > 0:
                logger(f"[{server_name}] ⚠ {delta_dirs} extra folders extracted")
        logger(f"[{server_name}] -----------------------------------")

    def apply(self, zip_path):
        srv_dir = os.path.join(get_root_dir(), self.server_name)
        ts = time.strftime("%Y%m%d%H%M%S")
        tmp_dir = os.path.join(self.pending_folder, f"tmp_{ts}")
        shutil.rmtree(tmp_dir, ignore_errors=True)
        os.makedirs(tmp_dir, exist_ok=True)
        zip_name = os.path.basename(zip_path)
        self.safe_log(f"[{self.server_name}] === Begin update ({zip_name}) ===")

        def count_entries(path):
            files = dirs = 0
            for _, dnames, fnames in os.walk(path):
                files += len(fnames)
                dirs += len(dnames)
            return files, dirs

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                names = zf.namelist()
                zip_files = sum(1 for n in names if not n.endswith("/"))
                zip_dirs = sum(1 for n in names if n.endswith("/"))
                zf.extractall(tmp_dir)
            self.safe_log(f"[{self.server_name}] ZIP extracted ({zip_files} files, {zip_dirs} dirs)")
        except Exception as e:
            self.safe_log(f"[{self.server_name}] ERROR extracting ZIP: {e}")

        try:
            extracted_files, extracted_dirs = count_entries(tmp_dir)
            self.log_extraction_summary(
                self.server_name,
                zip_files, zip_dirs,
                extracted_files, extracted_dirs,
                self.safe_log
            )
        except Exception as e:
            self.safe_log(f"[{self.server_name}] ERROR in summary log: {e}")

        try:
            self.safe_log(f"[{self.server_name}] Stopping server…")
            if hasattr(self.gui, "stop_server"):
                self.gui.stop_server(self.server_name)
            else:
                subprocess.run(["net", "stop", self.server_name], check=True)
            self.safe_log(f"[{self.server_name}] Server stopped")
        except Exception as e:
            self.safe_log(f"[{self.server_name}] ERROR stopping server: {e}")

        try:
            backup_zip = os.path.join(self.backup_folder, f"{self.server_name}_backup_{ts}.zip")
            with zipfile.ZipFile(backup_zip, "w", zipfile.ZIP_DEFLATED) as zf:
                if os.path.isdir(srv_dir):
                    for root, _, files in os.walk(srv_dir):
                        for f in files:
                            full = os.path.join(root, f)
                            arc = os.path.relpath(full, srv_dir)
                            zf.write(full, arc)
            self.safe_log(f"[{self.server_name}] Backup saved → {backup_zip}")
        except Exception as e:
            self.safe_log(f"[{self.server_name}] ERROR during backup: {e}")

        try:
            if os.path.isdir(srv_dir):
                shutil.rmtree(srv_dir)
            os.makedirs(srv_dir, exist_ok=True)
            for item in os.listdir(tmp_dir):
                src = os.path.join(tmp_dir, item)
                dst = os.path.join(srv_dir, item)
                if os.path.isdir(src):
                    shutil.copytree(src, dst, dirs_exist_ok=True)
                else:
                    shutil.copy2(src, dst)
            self.safe_log(f"[{self.server_name}] Copied new version into place")
        except Exception as e:
            self.safe_log(f"[{self.server_name}] ERROR copying new version: {e}")

        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            self.safe_log(f"[{self.server_name}] Temp dir removed")
        except Exception as e:
            self.safe_log(f"[{self.server_name}] WARNING removing temp dir: {e}")

        try:
            self.safe_log(f"[{self.server_name}] Restarting server…")
            mbm = self.gui.main_branch_manager
            port = next((p for name, p, _ in mbm.servers if name == self.server_name), None)
            if port is not None:
                app_dir = os.path.join(get_root_dir(), self.server_name)
                mbm.start_server(self.server_name, port, app_dir)
                self.safe_log(f"[{self.server_name}] Server restarted on port {port}")
            else:
                self.safe_log(f"[{self.server_name}] ERROR: port not found, cannot restart")
        except Exception as e:
            self.safe_log(f"[{self.server_name}] ERROR restarting server: {e}")

        try:
            self.gui.draw_tab_buttons()
            self.gui.update_status_row()
            self.safe_log(f"[{self.server_name}] GUI refreshed")
        except Exception:
            self.safe_log(f"[{self.server_name}] GUI update failed (non-fatal)")

        try:
            if delete_file_with_retries(zip_path):
                self.safe_log(f"[{self.server_name}] Pending ZIP deleted")
            else:
                self.safe_log(f"[{self.server_name}] WARNING – could not delete pending ZIP")
        except Exception as e:
            self.safe_log(f"[{self.server_name}] Unexpected error deleting ZIP: {e}")

        self.safe_log(f"[{self.server_name}] === Update complete ===")

        try:
            notify_booted([self.server_name], just_updated=True)
        except Exception as e:
            self.safe_log(f"[{self.server_name}] Failed to notify boot: {e}")

    def package_and_send(self):
        threading.Thread(target=self._do_package_and_send, daemon=True).start()

    def _do_package_and_send(self):
        mgr   = self.gui.update_and_receive
        audit = mgr._log_audit
        audit(f"[{self.server_name}] package_and_send")
        self.safe_log(f"[{self.server_name}] ✉️ Package & Update invoked")
        src_dir = os.path.join(get_root_dir(), self.server_name)
        if not os.path.isdir(src_dir):
            msg = f"[{self.server_name}] Source directory missing → abort"
            audit(msg); self.safe_log(msg)
            return

        ts       = time.strftime("%Y%m%d%H%M%S")
        filename = f"{self.server_name}_{ts}.zip"
        zip_path = os.path.join(self.update_folder, filename)

        try:
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for root, _, files in os.walk(src_dir):
                    for f in files:
                        full = os.path.join(root, f)
                        arc  = os.path.relpath(full, src_dir)
                        zf.write(full, arc)
            self.safe_log(f"[{self.server_name}] Packaged → {zip_path}")
        except Exception as e:
            audit(f"[{self.server_name}] ERROR packaging: {e}")
            self.safe_log(f"[{self.server_name}] Packaging error: {e}")
            return

        base       = _get_update_node_base(self.gui)
        upload_url = f"{base}/updates/"
        audit(f"[{self.server_name}] Uploading ZIP to {upload_url} (timeout=30s)")
        try:
            with open(zip_path, "rb") as fp:
                files = {"file": (filename, fp, "application/zip")}
                resp = requests.post(upload_url, files=files, timeout=30)
                resp.raise_for_status()
            self.safe_log(f"[{self.server_name}] Upload OK ({resp.status_code}) → {upload_url}")
            if delete_file_with_retries(zip_path):
                self.safe_log(f"[{self.server_name}] ZIP deleted: {zip_path}")
            else:
                self.safe_log(f"[{self.server_name}] WARNING – could not delete ZIP")
        except Exception as e:
            audit(f"[{self.server_name}] Upload failed: {e}")

class SelfUpdateHandler:
    def __init__(self, gui):
        self.gui        = gui
        self.stop_event = threading.Event()
        if getattr(sys, "frozen", False):
            app_root = os.path.dirname(sys.executable)
        else:
            module_dir = os.path.dirname(os.path.abspath(__file__))
            app_root   = os.path.abspath(os.path.join(module_dir, os.pardir))
        storage = os.path.join(app_root, "update_node_receive_storage")
        self.self_audit_path = os.path.join(storage, "self_update_audit.log")
        self._log_self_audit("[Init] SelfUpdater audit started")
        self.apply_log_path = os.path.join(storage, "self_update_application.log")
        self._log_self_apply("[Init] SelfUpdater application log started")
        self.update_folder = os.path.join(storage, "self_updates")
        os.makedirs(self.update_folder, exist_ok=True)

    def finish_init(self):
        self._log_self_audit("[OnBoot] Checking for self-update on boot")
        try:
            self.fetch_and_apply_on_boot()
        except Exception as e:
            self._log_self_apply(f"[OnBoot] exception: {e}")
            self._log_self_apply(traceback.format_exc())
        threading.Thread(target=self.poll_for_updates, daemon=True).start()
        self.schedule_daily_self_update()
        try:
            server_list = list(getattr(self.gui, "all_servers", ["Server Manager"]))
            notify_booted(server_list, just_updated=False)
        except Exception as e:
            log_audit(f"[BootNotify] Failed to notify boot at startup: {e}")

    def _log_self_audit(self, message: str, level: str = "info"):
        log_event("Self", "Update", message, level)

    def _log_self_apply(self, message: str, level: str = "info"):
        log_event("Self", "Update", message, level)

    def poll_for_updates(self, interval=300):
        self._log_self_audit(f"[Poll] every {interval}s")
        while not self.stop_event.is_set():
            self._log_self_audit("[Poll] tick")
            try:
                self.fetch_self_update()
            except Exception as e:
                self._log_self_apply(f"[Poll] exception: {e}")
                self._log_self_apply(traceback.format_exc())
            time.sleep(interval)

    def fetch_and_apply_on_boot(self):
        try:
            fn = self.get_latest_self()
            if fn:
                self._log_self_audit(f"[OnBoot] found self-update: {fn}")
                self.download_self(fn)
                path = os.path.join(self.update_folder, fn)
                if os.path.exists(path):
                    self._log_self_audit(f"[OnBoot] applying self-update from {path}")
                    self.apply(path)
        except Exception as e:
            self._log_self_apply(f"[OnBoot] exception: {e}")
            self._log_self_apply(traceback.format_exc())

    def fetch_self_update(self):
        self._log_self_audit("[Fetch] fetch_self_update called")
        try:
            fn = self.get_latest_self()
            if fn:
                self._log_self_audit(f"[Fetch] found self-update: {fn}")
                self.download_self(fn)
                path = os.path.join(self.update_folder, fn)
                if os.path.exists(path):
                    self._log_self_audit(f"[Fetch] applying self-update from {path}")
                    self.apply(path)
        except Exception as e:
            self._log_self_apply(f"[Fetch] exception: {e}")
            self._log_self_apply(traceback.format_exc())

    def get_latest_self(self):
        base = _updates_endpoint(self.gui)
        list_url = f"{base}/?server={urllib.parse.quote('Server Manager')}"
        self._log_self_audit(f"[List] GET {list_url}")
        try:
            r = requests.get(list_url, timeout=60)
            r.raise_for_status()
            files = r.json().get("files", [])
        except Exception as e:
            self._log_self_audit(f"[List] HTTP/JSON error: {e}")
            return None

        if "Server Manager.exe" not in files:
            self._log_self_audit("[List] 'Server Manager.exe' not present")
            return None

        head_url = f"{base}/{urllib.parse.quote('Server Manager.exe')}"
        self._log_self_audit(f"[Head] HEAD {head_url}")
        try:
            h = requests.head(head_url, timeout=30)
            h.raise_for_status()
            lm = h.headers.get("Last-Modified")
        except Exception as e:
            self._log_self_audit(f"[Head] HEAD error: {e}")
            return None

        if lm:
            remote_dt = email.utils.parsedate_to_datetime(lm)
            remote_ts = remote_dt.timestamp()
            local_ts = os.path.getmtime(sys.executable)
            self._log_self_audit(f"[Head] remote_ts={remote_ts}, local_ts={local_ts}")
            if remote_ts <= local_ts:
                self._log_self_audit("[Head] remote not newer → skipping")
                return None
        else:
            self._log_self_audit("[Head] no Last-Modified header → will update")

        self._log_self_audit("[Head] remote is newer → pulling update")
        return "Server Manager.exe"

    def download_self(self, fn):
        url = f"{_updates_endpoint(self.gui)}/{fn}"
        dst = os.path.join(self.update_folder, fn)
        self._log_self_audit(f"[Download] GET {url}")
        try:
            r = requests.get(url, stream=True, timeout=120)
            r.raise_for_status()
            with open(dst, "wb") as f:
                for chunk in r.iter_content(1024):
                    if chunk:
                        f.write(chunk)
            self._log_self_audit(f"[Download] saved to {dst}")
        except Exception as e:
            self._log_self_audit(f"[Download] error: {e}")

    def schedule_daily_self_update(self):
        def run():
            while True:
                now = time.localtime()
                secs = ((24 - now.tm_hour - 1) * 3600 +
                        (60 - now.tm_min - 1) * 60 +
                        (60 - now.tm_sec))
                time.sleep(secs)
                self._log_self_audit("[Daily] midnight check")
                try:
                    self.fetch_self_update()
                except Exception as e:
                    self._log_self_apply(f"[Daily] exception: {e}")
                    self._log_self_apply(traceback.format_exc())
                time.sleep(60)
        threading.Thread(target=run, daemon=True).start()

    def apply(self, path):
        try:
            if getattr(sys, "frozen", False):
                app_root = os.path.dirname(sys.executable)
            else:
                from update_and_receive import get_root_dir
                app_root = get_root_dir()

            backups_dir = os.path.join(app_root, "update_node_receive_storage", "backups")
            os.makedirs(backups_dir, exist_ok=True)

            try:
                pending_dir = self.gui.update_manager.pending_updates_folder
            except AttributeError as e:
                self._log_self_apply(f"[Apply] gui.update_manager missing or incomplete; retrying in 10s. Error: {e}")
                self._log_self_apply(traceback.format_exc())
                threading.Timer(10, lambda: self.apply(path)).start()
                return

            self._log_self_apply(f"[Apply] checking pending folder: {pending_dir}")
            if not os.path.exists(pending_dir):
                self._log_self_apply(f"[Apply] WARNING: pending_dir does not exist: {pending_dir}")

            try:
                pending = [f for f in os.listdir(pending_dir) if f.lower().endswith(".zip")]
            except Exception as e:
                self._log_self_apply(f"[Apply] os.listdir() failed on pending_dir: {e}")
                self._log_self_apply(traceback.format_exc())
                return

            if pending:
                msg = f"[Apply] deferring EXE-update; {len(pending)} ZIP(s) still pending"
                self._log_self_audit(msg)
                self._log_self_apply(msg)
                threading.Thread(
                    target=self._deferred_apply,
                    args=(path, backups_dir),
                    daemon=True
                ).start()
                return

            self._do_apply(path, backups_dir)

        except Exception as e:
            self._log_self_apply(f"[Apply] exception: {e}")
            self._log_self_apply(traceback.format_exc())


    def _deferred_apply(self, path, backups_dir):
        try:
            try:
                pending_dir = self.gui.update_manager.pending_updates_folder
            except AttributeError as e:
                self._log_self_apply(f"[Deferred] gui.update_manager missing; retrying apply in 10s. Error: {e}")
                self._log_self_apply(traceback.format_exc())
                threading.Timer(10, lambda: self.apply(path)).start()
                return

            self._log_self_apply(f"[Deferred] started watching {pending_dir}")
            while True:
                time.sleep(5)
                try:
                    pending = [f for f in os.listdir(pending_dir) if f.lower().endswith(".zip")]
                    self._log_self_apply(f"[Deferred] checked: {len(pending)} ZIP(s) found")
                except Exception as e:
                    self._log_self_apply(f"[Deferred] os.listdir() failed: {e}")
                    self._log_self_apply(traceback.format_exc())
                    return

                if not pending:
                    msg = "[Apply] pending cleared → proceeding with EXE swap"
                    self._log_self_audit(msg)
                    self._log_self_apply(msg)
                    self._do_apply(path, backups_dir)
                    break

        except Exception as e:
            self._log_self_apply(f"[Deferred] exception: {e}")
            self._log_self_apply(traceback.format_exc())

    def _do_apply(self, path, backups_dir):
        try:
            fn, ext = os.path.splitext(os.path.basename(path))
            ts = time.strftime("%Y%m%d%H%M%S")
            stamped = f"{fn}_{ts}{ext}"
            dst = os.path.join(backups_dir, stamped)

            try:
                shutil.move(path, dst)
                self._log_self_apply(f"[Apply] backed up EXE to {dst}")
            except Exception as e:
                self._log_self_apply(f"[Apply] move error: {e}")
                self._log_self_apply(traceback.format_exc())
                return

            try:
                launch_updater_helper(sys.executable, dst, backups_dir)
                self._log_self_apply("[Apply] launched updater helper for EXE swap")
            except Exception as e:
                self._log_self_apply(f"[Apply] helper launch error: {e}")
                self._log_self_apply(traceback.format_exc())

        except Exception as e:
            self._log_self_apply(f"[do_apply] exception: {e}")
            self._log_self_apply(traceback.format_exc())

    def stop(self):
        self._log_self_audit("[Stop] SelfUpdateHandler stopping")
        self.stop_event.set()
