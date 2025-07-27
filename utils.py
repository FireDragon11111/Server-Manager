# File: server_manager/utils.py
# -----------------------------
# Provides utility functions for the ServerManager application, including root
# directory determination, process checks, port management, state tracking, file
# gathering, GUI refreshing, and JSON config management (now including arbitrary keys).

import os
import sys
import re
import socket
import psutil
import json
import tkinter as tk
from multiprocessing import Process
import webview
import logging
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

CONFIG_PATH = 'servers.json'

def resource_path(relative_path):
    """ Get absolute path to a resource, works for PyInstaller as well. """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        widget.bind("<Enter>", self._enter)
        widget.bind("<Leave>", self._leave)

    def _enter(self, event=None):
        self._schedule()

    def _leave(self, event=None):
        self._unschedule()
        self._hide_tip()

    def _schedule(self):
        self._after_id = self.widget.after(800, self._show_tip)

    def _unschedule(self):
        if hasattr(self, "_after_id"):
            self.widget.after_cancel(self._after_id)
            del self._after_id

    def _show_tip(self):
        if self.tip_window or not self.text:
            return
        x, y, _, cy = self.widget.bbox("insert") or (0, 0, 0, 0)
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + cy + 10
        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            tw, text=self.text, justify=tk.LEFT,
            background="#ffffe0", relief=tk.SOLID, borderwidth=1,
            font=("tahoma", "8", "normal")
        )
        label.pack(ipadx=4, ipady=2)

    def _hide_tip(self):
        if self.tip_window:
            self.tip_window.destroy()
            self.tip_window = None

#=======================
# 2. STATETRACKER CLASS
#=======================
class StateTracker:
    """
    Tracks the state of objects or components and determines if an update is necessary.
    """
    def __init__(self):
        self.state = {}

    def update_state(self, key, new_value):
        current = self.state.get(key)
        if current != new_value:
            self.state[key] = new_value
            return True
        return False

    def get_state(self, key):
        return self.state.get(key)

    def reset_state(self, key):
        if key in self.state:
            del self.state[key]

#=======================
# 3. GET_ROOT_DIR FUNCTION
#=======================
def get_root_dir():
    """
    Returns the root directory, which is the parent directory of the script's location.
    """
    script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    return os.path.abspath(os.path.join(script_dir, '..'))

def get_app_root():
    """
    Returns the directory containing the running EXE (when bundled) or,
    when running from source, the parent of this utils.py (i.e. the project root).
    This is the true 'Server Manager' folder for placing updates/backups.
    """
    import sys, os
    if getattr(sys, "frozen", False):
        # bundled .exe: sys.executable lives in Server Manager\
        return os.path.dirname(sys.executable)
    else:
        # running from source: utils.py is in server_manager/, so parent is root
        this_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.abspath(os.path.join(this_dir, os.pardir))

#=======================
# 4. IS_PROCESS_RUNNING
#=======================
def is_process_running(process_name):
    """
    Checks if a process with the given name is currently running.
    """
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] and process_name.lower() in proc.info['name'].lower():
            return True
    return False

#=======================
# 5. GET_NEXT_AVAILABLE_PORT
#=======================
def get_next_available_port(start_port: int = 8000,
                            end_port: int = 9000,
                            skip: set[int] | None = None) -> int:
    skip = skip or set()
    for port in range(start_port, end_port):
        if port in skip:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('localhost', port)) != 0:   # port not in use
                return port
    raise RuntimeError("No available ports found in the specified range.")

#=======================
# 6. IS_PORT_IN_USE
#=======================
def is_port_in_use(port):
    """
    Checks if a specific TCP port is currently in use.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

#=======================
# 7. CLOSE_OPEN_FILES
#=======================
def close_open_files(server_name):
    """
    Attempts to close any open file handles associated with the given server.
    """
    for proc in psutil.process_iter(['name', 'open_files']):
        if proc.info['name'] and server_name.lower() in proc.info['name'].lower():
            try:
                for f in proc.info['open_files'] or []:
                    os.close(f.fd)
            except Exception:
                pass

#=======================
# 8. GATHER_FILES_TO_OPEN
#=======================
def gather_files_to_open(base_dir, exclude_dirs, exclude_patterns, file_extensions=None):
    """
    Gathers all relevant files to open from a directory.
    """
    files_to_open = []
    for root, dirs, files in os.walk(base_dir, topdown=True):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for file in files:
            if any(re.fullmatch(p.replace('*', '.*'), file) for p in exclude_patterns):
                continue
            if file_extensions is None or file.endswith(file_extensions):
                files_to_open.append(os.path.join(root, file))
    return files_to_open

#=======================
# 9. OPEN_BROWSER_WINDOW
#=======================
def run_webview_browser(url, title):
    """
    Initializes PyWebView and creates a browser window.
    """
    def on_loaded():
        js = """
        (function() {
            window.open = function(u){ window.location.href = u; };
            document.querySelectorAll('a[target="_blank"]').forEach(a=>a.removeAttribute('target'));
        })();
        """
        window.evaluate_js(js)

    window = webview.create_window(title, url)
    window.events.loaded += on_loaded
    webview.start()

def open_browser_window(url, server_name):
    """
    Opens the given URL in a standalone PyWebView browser window.
    """
    from utils import load_server_config, allocate_port_for_server
    cfg = load_server_config(CONFIG_PATH)
    port = cfg['servers'].get(server_name) or allocate_port_for_server(server_name)
    if "{port}" in url:
        url = url.format(port=port)
    else:
        url = f"http://127.0.0.1:{port}"
    title = f"Viewing {server_name}"
    Process(target=run_webview_browser, args=(url, title)).start()

#=======================
# 10. REFRESH_GUI
#=======================
def refresh_gui(frame, items, create_item_fn, persistent_widgets=None):
    """
    Refreshes GUI components dynamically, excluding persistent widgets.
    """
    if not frame or not frame.winfo_exists():
        print(f"[DEBUG] Frame {frame} invalid.")
        return False
    persistent_widgets = persistent_widgets or []
    try:
        for w in frame.winfo_children():
            if w not in persistent_widgets:
                w.destroy()
    except tk.TclError as e:
        print(f"[DEBUG] refresh_gui destroy error: {e}")
        return False
    try:
        for item in items:
            create_item_fn(frame, *item)
        return True
    except Exception as e:
        print(f"[DEBUG] refresh_gui create error: {e}")
        return False

#=======================
# 11. JSON CONFIG MANAGEMENT
#=======================
def create_default_config(path):
    if not os.path.exists(path):
        default = {
            "servers": {},
            "update_sending_mode": False,
            "running_servers": [],
            "nginx_running": True,
            "notepad_path":        "Notepad++/notepad++.exe",
            "nginx_executable":    "nginx/nginx.exe",
            "nginx_conf":          "nginx/conf/nginx.conf",
            "certbot_live_dir":    "C:/Certbot/live",
            "update_node_url":       "https://update-node.firecrafting.net",
            "update_node_local_url": "http://127.0.0.1:5001",
            "admin_email": "FireDragon111111@gmail.com"
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(default, f, indent=2)

def upgrade_server_config(path):
    defaults = {
        "notepad_path":        "Notepad++/notepad++.exe",
        "nginx_executable":    "nginx/nginx.exe",
        "nginx_conf":          "nginx/conf/nginx.conf",
        "certbot_live_dir":    "C:/Certbot/live",
        "update_node_url":       "https://update-node.firecrafting.net",
        "update_node_local_url": "http://127.0.0.1:5001",
        "admin_email":         "FireDragon111111@gmail.com",
    }
    cfg = load_server_config(path)
    changed = False
    for key, value in defaults.items():
        if key not in cfg:
            cfg[key] = value
            changed = True
    if "servers" in cfg:
        running = set(cfg.get("running_servers", []))
        for srv in list(cfg["servers"]):
            if running and srv not in running:
                del cfg["servers"][srv]
                changed = True

    if changed:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)

def load_server_config(path):
    create_default_config(path)
    try:
        with open(path, 'r') as f:
            cfg = json.load(f)
    except Exception as e:
        print(f"[ERROR] load config: {e}")
        cfg = {
            "servers": {},
            "update_sending_mode": False,
            "running_servers": [],
            "nginx_running": False
        }
    if 'servers' not in cfg:
        cfg['servers'] = {}
    if 'update_sending_mode' not in cfg:
        cfg['update_sending_mode'] = False
    if 'running_servers' not in cfg:
        cfg['running_servers'] = []
    if 'nginx_running' not in cfg:
        cfg['nginx_running'] = True

    return cfg

def update_server_config(path, server_name, port):
    """
    Updates the mapping of server_name→port.
    """
    try:
        cfg = load_server_config(path)
        cfg['servers'][server_name] = port
        with open(path, 'w') as f:
            json.dump(cfg, f, indent=2)
    except Exception as e:
        print(f"[ERROR] update_server_config: {e}")

def remove_server_from_config(path, server_name):
    """
    Removes a server entry from config.
    """
    cfg = load_server_config(path)
    if server_name in cfg['servers']:
        del cfg['servers'][server_name]
        with open(path, 'w') as f:
            json.dump(cfg, f, indent=2)

def allocate_port_for_server(server_name: str) -> int:
    cfg = load_server_config(CONFIG_PATH)
    existing = cfg['servers'].get(server_name)
    if existing:
        return existing

    used_ports = set(cfg['servers'].values())
    port = get_next_available_port(start_port=8000,
                                   end_port=9000,
                                   skip=used_ports)

    update_server_config(CONFIG_PATH, server_name, port)
    return port

def release_port_for_server(server_name):
    remove_server_from_config(CONFIG_PATH, server_name)

# --- New generic getters/setters for arbitrary config keys ---
def get_config_value(path, key, default=None):
    cfg = load_server_config(path)
    return cfg.get(key, default)

def set_config_value(path, key, value):
    try:
        cfg = load_server_config(path)
        cfg[key] = value
        with open(path, 'w') as f:
            json.dump(cfg, f, indent=2)
    except Exception as e:
        print(f"[ERROR] set_config_value({key}): {e}")

# Ensure default config on import
create_default_config(CONFIG_PATH)

def get_log_base_dir():
    # Always use directory of running EXE (if frozen), else script directory
    if getattr(sys, "frozen", False):
        base = Path(sys.executable).parent
    else:
        base = Path(__file__).resolve().parent.parent
    return base / "logs"

def ensure_log_folder(category, subcategory=None):
    base = get_log_base_dir()
    if category.lower() == "self":
        path = base / "Self"
        if subcategory:
            path = path / subcategory
    elif category.lower() == "nodes":
        path = base / "Nodes"
        if subcategory:
            path = path / subcategory
    else:
        path = base / category
        if subcategory:
            path = path / subcategory
    path.mkdir(parents=True, exist_ok=True)
    return path

def get_logger(category, subcategory=None, log_name="log", when="midnight", backupCount=14):
    """
    Get a logger that writes to logs/<category>/<subcategory>/log_YYYY-MM-DD.log
    Rotates daily at midnight, keeps up to backupCount log files.
    """
    folder = ensure_log_folder(category, subcategory)
    log_file = folder / f"{log_name}.log"
    logger_name = f"{category}.{subcategory or 'main'}"
    logger = logging.getLogger(logger_name)
    if not logger.hasHandlers():
        handler = TimedRotatingFileHandler(str(log_file), when=when, backupCount=backupCount, encoding='utf-8')
        formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')
        handler.setFormatter(formatter)
        logger.setLevel(logging.INFO)
        logger.addHandler(handler)
        logger.propagate = False  # Prevent double logging if root logger is configured
    return logger

def log_event(category, subcategory, message, level="info"):
    """
    Shortcut to log a message to the right log file.
    """
    logger = get_logger(category, subcategory)
    log_fn = getattr(logger, level.lower(), logger.info)
    log_fn(message)

def get_cert_runtime_logger():
    folder = ensure_log_folder("Self", "CertRuntime")
    log_file = folder / "session.log"
    logger_name = "Self.CertRuntime.Session"
    logger = logging.getLogger(logger_name)
    for h in list(logger.handlers):
        try:
            h.close()
        except Exception:
            pass
        logger.removeHandler(h)
    handler = TimedRotatingFileHandler(
        str(log_file),
        when="midnight",
        backupCount=1,
        encoding="utf-8"
    )
    formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    logger.propagate = False
    return logger

upgrade_server_config(CONFIG_PATH)
CERTBOT_LIVE_DIR = get_config_value(CONFIG_PATH, "certbot_live_dir", os.path.join("C:/", "Certbot", "live"))