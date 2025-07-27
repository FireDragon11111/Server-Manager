"""
File: server_manager/gui.py
---------------------------
Handles all GUI-related functionalities, constructs the main window,
and integrates components from other modules.
"""

#=======================
# 1. IMPORTS
#=======================
import os
import sys
import time
import threading
import subprocess
import socket
import psutil
import requests
import base64
import zipfile
from datetime import datetime, timezone
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog, Toplevel, Label
from PIL import Image, ImageTk
from pathlib import Path
from nginx_manager import NginxManager
from main_branch_manager import MainBranchManager
from test_branch_manager import TestBranchManager
from update_and_receive import UpdateAndReceive, SelfUpdateHandler
from utils import (
    allocate_port_for_server,
    get_root_dir,
    StateTracker,
    get_config_value,
    set_config_value,
    CONFIG_PATH,
    resource_path,
    ToolTip,
    get_logger,
    get_cert_runtime_logger,
    log_event,
    ensure_log_folder
)
from base64_variables import WATCHDOG_EXE_B64, NOTEPAD_PLUSPLUS, NGINX

if getattr(sys, "frozen", False):
    base_dir = os.path.dirname(sys.executable)
else:
    base_dir = os.path.dirname(os.path.abspath(__file__))

def relaunch_after_delay(delay=3):
    """
    Spawn a new process to relaunch this program after `delay` seconds.
    """
    python = sys.executable
    script = sys.argv[0]
    args = sys.argv[1:]
    # This launches a tiny one-liner Python process that waits, then launches our main app again
    cmd = [
        python,
        "-c",
        (
            f"import time,subprocess,sys; "
            f"time.sleep({delay}); "
            f"subprocess.Popen([sys.executable, {repr(script)}] + sys.argv[1:])"
        )
    ] + [script] + args
    subprocess.Popen(cmd, close_fds=True)

def ensure_dependency_unzipped(base_dir, folder_name, base64_zip_data):
    target_dir = os.path.join(base_dir, folder_name)
    if os.path.exists(target_dir) and os.path.isdir(target_dir) and len(os.listdir(target_dir)) > 0:
        return  # Already extracted

    zip_path = os.path.join(base_dir, f"{folder_name}.zip")
    try:
        with open(zip_path, "wb") as f:
            f.write(base64.b64decode(base64_zip_data))
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(target_dir)
    finally:
        if os.path.exists(zip_path):
            try:
                os.remove(zip_path)
            except Exception:
                pass

ensure_dependency_unzipped(base_dir, "Notepad++", NOTEPAD_PLUSPLUS)
ensure_dependency_unzipped(base_dir, "nginx", NGINX)

def extract_watchdog_exe(dest_path):
    try:
        if os.path.exists(dest_path):
            os.remove(dest_path)
    except Exception:
        pass
    exe_bytes = base64.b64decode(WATCHDOG_EXE_B64)
    with open(dest_path, 'wb') as f:
        f.write(exe_bytes)

def launch_watchdog():
    import sys
    import subprocess
    import os
    if getattr(sys, "frozen", False):
        base_dir = os.path.dirname(sys.executable)
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))
    exe_path = os.path.join(base_dir, "watchdog_checker.exe")
    extract_watchdog_exe(exe_path)

    args = [exe_path]

    creationflags = (
        subprocess.CREATE_NEW_PROCESS_GROUP |
        subprocess.DETACHED_PROCESS |
        getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    )

    proc = subprocess.Popen(
        args,
        cwd=base_dir,
        creationflags=creationflags,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return proc

def kill_existing_watchdog():
    exe_name = "watchdog_checker.exe"
    my_pid = os.getpid()
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            if proc.info['pid'] == my_pid:
                continue
            if proc.info['name'] and exe_name in proc.info['name'].lower():
                proc.terminate()
                proc.wait(timeout=2)
        except Exception:
            continue

def ensure_watchdog():
    kill_existing_watchdog()
    launch_watchdog()


def start_heartbeat_writer():
    def heartbeat():
        if getattr(sys, "frozen", False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.abspath(__file__))
        info_path = os.path.join(base_dir, "running.info")
        while True:
            try:
                with open(info_path, "w") as f:
                    f.write(f"pid={os.getpid()}\n")
                    f.write(f"timestamp={datetime.now(timezone.utc).isoformat()}\n")
            except Exception:
                pass
            time.sleep(5)
    t = threading.Thread(target=heartbeat, daemon=True)
    t.start()

#=======================
# 2. SERVERMANAGERGUI CLASS
#=======================
class ServerManagerGUI(tk.Tk):
    #-----------------------
    # 2.1 INITIALIZATION
    #-----------------------
    def __init__(self):
        super().__init__()
        ensure_watchdog()
        start_heartbeat_writer()
        self.title("Server Manager")
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.gui_events_logger = get_logger("Self", "GUI_Events")
        self.gui_events_logger.info("Server Manager GUI started.")
        icon_path = resource_path("Server_Manager_Icon.ico")
        if os.path.exists(icon_path):
            try:
                self.iconbitmap(icon_path)
            except tk.TclError:
                self.gui_events_logger.warning(f"Could not set iconbitmap from {icon_path}")
            try:
                img = Image.open(icon_path)
                photo = ImageTk.PhotoImage(img)
                self.iconphoto(False, photo)
                self._window_icon = photo
            except Exception as e:
                self.gui_events_logger.warning(f"Could not set iconphoto: {e}")
        else:
            self.gui_events_logger.warning(f"Icon not found at {icon_path}")
        self.update_manager       = UpdateAndReceive(self)
        self.self_update_handler  = SelfUpdateHandler(self)
        self.nginx_manager        = NginxManager(self)
        self.main_branch_manager  = MainBranchManager(self)
        self.test_branch_manager  = TestBranchManager(self)
        self._update_node_proc    = None
        initial_mode = get_config_value(CONFIG_PATH, "update_sending_mode", False)
        self.update_mode_var = tk.BooleanVar(value=initial_mode)
        self.create_widgets()
        self.after_idle(self._deferred_logging_startup)
        self.after_idle(self._background_update_and_receive_init)
        self.after_idle(self._background_startup)

    def _background_update_and_receive_init(self):
        def worker():
            self.update_manager.finish_init()
            self.self_update_handler.finish_init()
        threading.Thread(target=worker, daemon=True).start()

    def _background_startup(self):
        if self.update_mode_var.get():
            threading.Thread(target=self.start_update_node_server, daemon=True).start()
        def _worker():
            self._restore_servers()
            self._startup_nginx_workflow()
        threading.Thread(target=_worker, daemon=True).start()
        self.nginx_manager.ensure_directories()

    def _restore_servers(self):
        previously = get_config_value(CONFIG_PATH, "running_servers", [])
        threads = []
        for name, port, ssl in self.main_branch_manager.servers:
            if name in previously:
                app_dir = os.path.join(get_root_dir(), name)
                t = threading.Thread(
                    target=self.main_branch_manager.start_server,
                    args=(name, port, app_dir),
                    daemon=True
                )
                threads.append(t)
                t.start()
        for name, port, ssl in self.test_branch_manager.test_branches:
            if name in previously:
                t = threading.Thread(
                    target=self.test_branch_manager.start_test_branch,
                    args=(name, port),
                    daemon=True
                )
                threads.append(t)
                t.start()

    def _deferred_logging_startup(self):
        self.start_cert_runtime_log()
        self.schedule_cert_log_entry()

    def log_cert_runtime_event(self, event=None):
        now = datetime.now()
        date_str = now.strftime("%B %d, %Y | %H:%M:%S.%f")[:-3]
        if event:
            line = f"{date_str} | {event}"
        else:
            line = date_str
        self.cert_logger.info(line)

    def load_icon(self, name, size=(16,16)):
        path = resource_path(os.path.join("assets", name))
        if not os.path.exists(path):
            raise FileNotFoundError(f"Missing icon: {path}")
        img = Image.open(path).resize(size, Image.Resampling.LANCZOS)
        return ImageTk.PhotoImage(img)

    def _startup_nginx_workflow(self):
        self.gui_events_logger.info("NGINX startup workflow initiated.")
        servers = (
            self.main_branch_manager.servers
            + self.test_branch_manager.test_branches
        )
        for domain, port, _ in servers:
            self.gui_events_logger.info(f"Ensuring cert for {domain}")
            self.nginx_manager.ensure_certificate(domain)
        self.nginx_manager.generate_conf()
        self.nginx_manager.reload_conf()
        self.gui_events_logger.info("NGINX startup workflow completed.")


    #-----------------------
    # 2.2 WIDGET CREATION
    #-----------------------
    def create_widgets(self):
        self.main_frame = ttk.Frame(self, height=800)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.main_frame.pack_propagate(False)
        self.tab_buttons_frame = tk.Frame(self.main_frame)
        self.tab_buttons_frame.pack(fill=tk.X, pady=(5,0))
        self.tab_contents_frame = tk.Frame(self.main_frame)
        self.tab_contents_frame.pack(fill=tk.BOTH, expand=True)
        self.tab_frames = {}
        self.tab_order  = []
        self.active_tab = None
        self.loading_label = tk.Label(self.main_frame, text="Loading servers, please wait...", font=("Segoe UI", 11))
        self.loading_label.pack(pady=50)
        import threading
        threading.Thread(target=self._background_detect_and_populate, daemon=True).start()
        nginx_frame = tk.Frame(self.tab_contents_frame)
        self.tab_frames["NGINX"] = nginx_frame
        self.tab_order.insert(0, "NGINX")
        header = tk.Frame(nginx_frame)
        header.pack(anchor="w", pady=(10,5), padx=10)
        self.nginx_manager.status_dot = tk.Canvas(header, width=20, height=20, highlightthickness=0)
        color = "green" if self.nginx_manager.is_nginx_running() else "red"
        self.nginx_manager.status_dot.create_oval(2,2,18,18, fill=color, outline="")
        self.nginx_manager.status_dot.pack(side=tk.LEFT)
        tk.Label(header, text="NGINX Management", font=("Segoe UI",10,"bold"))\
          .pack(side=tk.LEFT, padx=6)
        icon_row = ttk.Frame(nginx_frame)
        icon_row.pack(fill=tk.X, pady=(0,5), padx=10)
        icons = {
            "start":   self.load_icon("Play Icon.png"),
            "stop":    self.load_icon("Stop Icon.png"),
            "restart": self.load_icon("Restart Icon.png"),
            "folder":  self.load_icon("View Files Icon.png"),
            "reload":  self.load_icon("Reload Icon.png"),
            "add":     self.load_icon("Create New Test Branch Icon.png"),
        }
        def add_btn(parent, key, command, tooltip):
            btn = ttk.Button(parent, image=icons[key], width=3, command=command)
            btn.image = icons[key]
            btn.pack(side=tk.LEFT, padx=2)
            ToolTip(btn, tooltip)
            return btn
        self.nginx_manager.btn_start   = add_btn(icon_row, "start",   self.nginx_manager.start_nginx,   "Start NGINX")
        self.nginx_manager.btn_stop    = add_btn(icon_row, "stop",    self.nginx_manager.stop_nginx,    "Stop NGINX")
        self.nginx_manager.btn_restart = add_btn(icon_row, "restart", self.nginx_manager.restart_nginx, "Restart NGINX")
        ttk.Label(icon_row, text="|").pack(side=tk.LEFT, padx=4)
        add_btn(icon_row, "folder", self.nginx_manager.open_nginx_conf, "Open NGINX Config Folder")
        add_btn(icon_row, "reload", self.nginx_manager.reload_conf,     "Reload NGINX Config")
        ttk.Label(icon_row, text="|").pack(side=tk.LEFT, padx=4)
        add_btn(icon_row, "add", self.on_add_server_click, "Add New Server Directory")
        self.after(0, self.nginx_manager.update_button_states)
        chk = ttk.Checkbutton(
            nginx_frame,
            text="Update-Sending Mode",
            variable=self.update_mode_var,
            command=self.toggle_update_mode
        )
        chk.pack(anchor="w", pady=10, padx=10)
        log_notebook = ttk.Notebook(nginx_frame)
        log_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0,10))
        self.nginx_log_notebook = log_notebook
        self._setup_all_logs_tabs(log_notebook)
        self.draw_tab_buttons()
        if self.tab_order:
            self.show_tab(self.tab_order[0])

    def _background_detect_and_populate(self):
        self.main_branch_manager.detect_servers()
        self.test_branch_manager.detect_test_branches()
        self.after(0, self._servers_ready)

    def _servers_ready(self):
        if hasattr(self, "loading_label") and self.loading_label.winfo_exists():
            self.loading_label.destroy()
        for name, port, ssl in self.main_branch_manager.servers:
            fr = tk.Frame(self.tab_contents_frame)
            self.tab_frames[name] = fr
            self.tab_order.append(name)
            self.main_branch_manager.create_server_buttons(fr, name, port, ssl)
            tb_name = f"testing.{name}"
            entry = next((tb for tb in self.test_branch_manager.test_branches if tb[0] == tb_name), None)
            if entry:
                tb_port, tb_ssl = entry[1], entry[2]
                self.test_branch_manager.create_test_branch_buttons(fr, tb_name, tb_port, tb_ssl)
        self.draw_tab_buttons()
        if self.tab_order:
            self.show_tab(self.tab_order[0])
        threading.Thread(target=self._post_detect_nginx_init, daemon=True).start()

    def _post_detect_nginx_init(self):
        self.nginx_manager.generate_conf()
        if get_config_value(CONFIG_PATH, "nginx_running", False):
            self.nginx_manager.start_nginx()

    def _setup_all_logs_tabs(self, notebook: ttk.Notebook):
        logs_root = Path(base_dir) / "logs"
        all_files = list(logs_root.rglob("*.log*"))
        groups: dict[str, list[Path]] = {}
        for p in all_files:
            folder = p.parent.name
            groups.setdefault(folder, []).append(p)
        newest_per_folder = {
            folder: max(paths, key=lambda f: f.stat().st_mtime)
            for folder, paths in groups.items()
        }
        for folder, log_path in sorted(newest_per_folder.items()):
            frame = ttk.Frame(notebook)
            txt   = scrolledtext.ScrolledText(
                frame, state='disabled', height=10, font=("Consolas", 9)
            )
            txt.pack(fill=tk.BOTH, expand=True)
            notebook.add(frame, text=folder)
            threading.Thread(
                target=self._tail_log_file,
                args=(txt, log_path),
                daemon=True
            ).start()

    def _tail_log_file(self, widget: scrolledtext.ScrolledText, file_path: Path):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.3)
                        continue
                    widget.after(0, self._append_log_line, widget, line.rstrip())
        except Exception as e:
            return

    def _append_log_line(self, widget: scrolledtext.ScrolledText, line: str):
        widget.config(state='normal')
        widget.insert(tk.END, line + "\n")
        widget.see(tk.END)
        widget.config(state='disabled')

    #-----------------------
    # 2.3 DRAW TAB BUTTONS
    #-----------------------
    def draw_tab_buttons(self):
        for w in self.tab_buttons_frame.winfo_children():
            w.destroy()

        b = tk.Frame(self.tab_buttons_frame, borderwidth=1, relief=tk.RAISED, padx=6, pady=3)
        b.pack(side=tk.LEFT, padx=2)
        color = "green" if self.nginx_manager.is_nginx_running() else "red"
        c = tk.Canvas(b, width=12, height=12, highlightthickness=0)
        c.create_oval(2,2,10,10, fill=color, outline="")
        c.pack(side=tk.LEFT)
        tk.Label(b, text="NGINX", anchor='w').pack(side=tk.LEFT, padx=(4,8), fill=tk.X)
        b.update_idletasks()
        b.bind("<Button-1>", lambda e: self.show_tab("NGINX"))
        for ch in b.winfo_children():
            ch.bind("<Button-1>", lambda e: self.show_tab("NGINX"))

        for name in self.tab_order:
            if name == "NGINX": 
                continue
            tf = tk.Frame(self.tab_buttons_frame, borderwidth=1, relief=tk.RAISED, padx=6, pady=3)
            tf.pack(side=tk.LEFT, padx=2)

            mr = self.main_branch_manager.is_waitress_running(name)
            clr = "green" if mr else "red"
            c1 = tk.Canvas(tf, width=12, height=12, highlightthickness=0)
            c1.create_oval(2,2,10,10, fill=clr, outline="")
            c1.pack(side=tk.LEFT)

            tk.Label(tf, text="/", font=("Segoe UI",10)).pack(side=tk.LEFT)

            tb = f"testing.{name}"
            ent = next((t for t in self.test_branch_manager.test_branches if t[0]==tb), None)
            if ent:
                tr = self.test_branch_manager.is_waitress_running(tb)
                clr2 = "blue" if tr else "orange"
            else:
                clr2 = "gray"
            c2 = tk.Canvas(tf, width=12, height=12, highlightthickness=0)
            c2.create_oval(2,2,10,10, fill=clr2, outline="")
            c2.pack(side=tk.LEFT)

            lbl = tk.Label(tf, text=name, anchor='w')
            lbl.pack(side=tk.LEFT, padx=(4,8), fill=tk.X)

            tf.update_idletasks()
            tf.bind("<Button-1>", lambda e,n=name: self.show_tab(n))
            for ch in tf.winfo_children():
                ch.bind("<Button-1>", lambda e,n=name: self.show_tab(n))

        self.after(20, self.fit_to_content)


    #-----------------------
    # 2.4 SHOW TAB
    #-----------------------
    def show_tab(self, key):
        if self.active_tab:
            self.tab_frames[self.active_tab].pack_forget()
        if key in self.tab_frames:
            self.tab_frames[key].pack(fill=tk.BOTH, expand=True)
            self.active_tab = key
            self.update_status_row()
            self.after(10, self.fit_to_content)


    #-----------------------
    # 2.5 ADD SERVER CONTROLS
    #-----------------------
    def create_add_server_controls(self, parent):
        f = ttk.Frame(parent)
        self.add_server_frame = f
        f.pack(fill=tk.X, pady=5)

        ttk.Label(f, text="New Server Directory:").pack(side=tk.LEFT)
        self.entry_new_server = ttk.Entry(f)
        self.entry_new_server.pack(side=tk.LEFT, padx=5)
        ttk.Button(f, text="Add Server", command=self.add_server).pack(side=tk.LEFT)



    #-----------------------
    # 2.6 LOGGING MECHANISM
    #-----------------------
    def log_message(self, msg, category="Main"):
        self.after(0, self._append_log, msg, category)

    def _append_log(self, msg, category):
        pass


    #-----------------------
    # 2.7 PERIODIC UPDATES
    #-----------------------
    def periodic_update(self):
        self.update_states()
        self.after(5000, self.periodic_update)

    def update_states(self):
        self.update_status_row()
        for name,_,_ in self.main_branch_manager.servers:
            running = self.main_branch_manager.is_waitress_running(name)
            self.main_branch_manager.update_gui_elements(name, running)
            tb = f"testing.{name}"
            for tname,_,_ in self.test_branch_manager.test_branches:
                if tname == tb:
                    tr = self.test_branch_manager.is_waitress_running(tb)
                    self.test_branch_manager.update_branch_button_states(tb, tr)
                    break
        self.draw_tab_buttons()


    #-----------------------
    # 2.8 STATUS ROW
    #-----------------------
    def update_status_row(self):
        return


    #-----------------------
    # 2.9 SERVER CONTROLS
    #-----------------------
    def start_all_servers(self):
        self.gui_events_logger.info("Starting all servers.")
        changed = False
        if not self.nginx_manager.is_nginx_running():
            self.nginx_manager.start_nginx(); changed = True
        for n,p,_ in self.main_branch_manager.servers:
            if not self.main_branch_manager.is_waitress_running(n):
                self.main_branch_manager.start_server(n, p, os.path.join(get_root_dir(), n)); changed = True
        for tn,p,_ in self.test_branch_manager.test_branches:
            if not self.test_branch_manager.is_waitress_running(tn):
                self.test_branch_manager.start_test_branch(tn, p); changed = True
        if changed:
            self.update_states()

    def stop_all_servers(self):
        self.gui_events_logger.info("Stopping all servers.")
        changed = False
        if self.nginx_manager.is_nginx_running():
            self.nginx_manager.stop_nginx(); changed = True
        for n,_,_ in self.main_branch_manager.servers:
            if self.main_branch_manager.is_waitress_running(n):
                self.main_branch_manager.stop_server(n); changed = True
        for tn,_,_ in self.test_branch_manager.test_branches:
            if self.test_branch_manager.is_waitress_running(tn):
                self.test_branch_manager.stop_test_branch(tn); changed = True
        if changed:
            self.update_states()

    def restart_all_servers(self):
        self.gui_events_logger.info("Restarting all servers.")
        self.stop_all_servers()
        self.start_all_servers()


    def on_add_server_click(self):
        """Scaffold a new main server + optional Argos translator service, then register & start it."""
        import os
        import tkinter as tk
        from tkinter import simpledialog, messagebox
        from utils import allocate_port_for_server, get_root_dir
        import json

        # 1) Ask for server directory name
        name = simpledialog.askstring(
            "New Server Directory",
            "Enter new server directory name:",
            parent=self
        )
        if not name:
            return

        # 2) Translation service?
        wants_translator = messagebox.askyesno(
            "Translation Service",
            "Also create an Argos‑powered translation server (+1000 port)?",
        )

        try:
            # 3.a) Compute paths & ports
            main_port = allocate_port_for_server(name)
            root_dir  = get_root_dir()
            srv_path  = os.path.join(root_dir, name)
            os.makedirs(srv_path, exist_ok=True)
            os.makedirs(os.path.join(srv_path, "logs", "translation_logs"), exist_ok=True)

            # 3.b) Write main.py
            main_py = f"""#!/usr/bin/env python3
import sys

from translator import perform_translation
from app import create_app

# Regenerate all translations
perform_translation()

app = create_app()

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else {main_port}
    app.run(host='0.0.0.0', port=port)
"""
            with open(os.path.join(srv_path, "main.py"), "w", encoding="utf-8") as f:
                f.write(main_py)

            tpl_dir = os.path.join(srv_path, "templates")
            os.makedirs(tpl_dir, exist_ok=True)

            # --------------------------------------------------------------------------- #
            # 3.c) Write translator.py (fully updated)                                    #
            # --------------------------------------------------------------------------- #
            trans_py = '''#!/usr/bin/env python3
import os
import re
import time
import logging

from argostranslate import package, translate
from bs4 import BeautifulSoup

# Configure languages here — keys are ISO codes, values are readable names
LANGUAGES = {
    'en': 'English',
    'es': 'Spanish',
    'fr': 'French',
    'nl': 'Dutch'
}

BASE_DIR      = os.path.dirname(__file__)
TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')
LOG_DIR       = os.path.join(BASE_DIR, 'logs', 'translation_logs')
os.makedirs(LOG_DIR, exist_ok=True)

# --------------------------------------------------------------------------- #
# logging                                                                     #
# --------------------------------------------------------------------------- #
log_file = os.path.join(LOG_DIR, f"translation_{int(time.time())}.log")
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s:%(message)s"
)
logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# ensure a model exists                                                       #
# --------------------------------------------------------------------------- #
def ensure_installed(from_code: str, to_code: str):
    \"\"\"Download & install the Argos package if not already installed.\"\"\"
    # ---------- Is the pair already installed? ---------------------------
    from_lang = next((l for l in translate.get_installed_languages()
                      if l.code == from_code), None)
    to_lang   = next((l for l in translate.get_installed_languages()
                      if l.code == to_code), None)

    if from_lang and to_lang:
        try:
            from_lang.get_translation(to_lang)   # raises if missing
            return                               # ✔ present
        except Exception:
            pass                                 # fall through

    # ---------- Otherwise download + install -----------------------------
    for pkg in package.get_available_packages():
        if pkg.from_code == from_code and pkg.to_code == to_code:
            package.install_from_path(pkg.download())
            logger.info(f\"Installed Argos model for {from_code} → {to_code}\")
            return

    raise RuntimeError(f\"No Argos package for {from_code} → {to_code}\")

# --------------------------------------------------------------------------- #
# translate an HTML/Jinja block-by-block                                      #
# --------------------------------------------------------------------------- #
def translate_blocks(raw: str, from_code: str, to_code: str) -> str:
    \"\"\"
    Finds every Jinja block in *raw* and translates only its inner HTML/text.
    Leaves `{% … %}` and `{{ … }}` unchanged so the translated file keeps
    extending base.html and evaluating expressions.
    \"\"\"
    pattern = re.compile(
        r'({%\\s*block\\s+\\w+\\s*%})(.*?)(\\s*{%\\s*endblock\\s*%})',
        re.DOTALL
    )

    def _replace(match):
        start_tag, inner, end_tag = match.groups()
        soup = BeautifulSoup(inner, 'html.parser')
        for node in soup.find_all(string=True):
            txt = node.strip()
            if not txt:
                continue
            if any(tok in txt for tok in (\"{%\", \"%}\", \"{{\", \"}}\", \"{#\", \"#}\")):
                continue
            if node.parent.name in (\"script\", \"style\"):
                continue
            node.replace_with(translate.translate(txt, from_code, to_code))
        return f\"{start_tag}{soup.decode()}{end_tag}\"

    return pattern.sub(_replace, raw)

# --------------------------------------------------------------------------- #
# rebuild templates/base.html with an enhanced language selector              #
# --------------------------------------------------------------------------- #
def generate_base():
    \"\"\"
    Re‑create *templates/base.html* and inject:
      • PWA manifest
      • Service‑worker registration
      • A polished language selector featuring a translatable label,
        current language on top, a divider, and an alphabetical list
        of the remaining languages (human‑readable names)
    \"\"\"
    content = \"\"\"<!DOCTYPE html>
<html lang=\"{{ selected_language }}\">
<head>
  <meta charset=\"UTF-8\">
  <title>{% block title %}My Site{% endblock %}</title>
  <link rel=\"manifest\" href=\"/static/manifest.json\">
  <style>
    .language-selector {
      position: fixed;
      bottom: 1rem;
      right: 1rem;
      background: rgba(255,255,255,0.95);
      border: 1px solid #ccc;
      border-radius: 4px;
      padding: 0.5rem 0.75rem;
      font-family: sans-serif;
      box-shadow: 0 2px 6px rgba(0,0,0,0.1);
      z-index: 1000;
    }
    .language-selector-label {
      display: block;
      margin-bottom: 0.25rem;
      font-weight: bold;
      font-size: 0.9rem;
    }
    .language-selector select {
      width: 100%;
      padding: 0.25rem;
      border-radius: 4px;
      border: 1px solid #aaa;
      font-size: 1rem;
      appearance: none;
      background: url(\"data:image/svg+xml;charset=US-ASCII,<svg xmlns='http://www.w3.org/2000/svg' width='10' height='5'><path fill='%23333' d='M0 0l5 5 5-5z'/></svg>\") no-repeat right 0.5rem center;
      background-color: white;
      background-size: 0.65em;
    }
    .language-selector option.current {
      font-weight: bold;
    }
    .language-divider {
      border-top: 1px solid #ccc;
      margin: 0.25rem 0;
    }
  </style>
</head>
<body>
  {% block content %}{% endblock %}

  <!-- Language selector -->
  <div class=\"language-selector\">
    <label class=\"language-selector-label\" for=\"language-select\">
      {{ select_language_phrase }}
    </label>
    <select id=\"language-select\" onchange=\"changeLanguage(this)\">
      <!-- current language -->
      <option class=\"current\" value=\"{{ request.path }}\">
        {{ language_names[selected_language] }}
      </option>
      <!-- divider -->
      <option class=\"language-divider\" disabled>──────────</option>
      <!-- remaining choices -->
      {% for lang in languages|sort %}
        {% if lang != selected_language %}
          <option value=\"{{ url_for('serve_translation', lang=lang, template=current_template) }}\">
            {{ language_names[lang] }}
          </option>
        {% endif %}
      {% endfor %}
    </select>
  </div>

  <script>
    function changeLanguage(sel) {
      window.location.href = sel.value;
    }
  </script>

  <!-- register service worker -->
  <script>
    if (\"serviceWorker\" in navigator) {
      window.addEventListener(\"load\", function() {
        navigator.serviceWorker.register(\"/service-worker.js\");
      });
    }
  </script>
</body>
</html>
\"\"\"
    target = os.path.join(TEMPLATES_DIR, 'base.html')
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, 'w', encoding='utf-8') as f:
        f.write(content)
    logger.info(f\"Generated enhanced base.html at {target}\")

# --------------------------------------------------------------------------- #
# drive the full site‑wide translation pass                                   #
# --------------------------------------------------------------------------- #
def perform_translation():
    \"\"\"Regenerate translations for every page in every configured language.\"\"\"
    pages = [
        fn for fn in os.listdir(TEMPLATES_DIR)
        if fn.endswith('.html') and fn != 'base.html'
    ]

    for page in pages:
        src = os.path.join(TEMPLATES_DIR, page)
        with open(src, 'r', encoding='utf-8') as f:
            raw = f.read()

        for iso_code, human_name in LANGUAGES.items():           # iso_code = 'es', etc.
            try:
                logger.info(f\"Translating {page} → {iso_code} ({human_name})\")
                ensure_installed('en', iso_code)                 # use ISO code here
                translated = translate_blocks(raw, 'en', iso_code)
                out_dir = os.path.join(TEMPLATES_DIR, iso_code)  # folder = 'es', 'fr', …
                os.makedirs(out_dir, exist_ok=True)
                out_path = os.path.join(out_dir, page)
                with open(out_path, 'w', encoding='utf-8') as outf:
                    outf.write(translated)
                logger.info(f\"Wrote translated template: {out_path}\")
            except Exception as e:
                logger.warning(f\"Skipping {iso_code} ({human_name}) for {page}: {e}\")

    generate_base()
    logger.info(\"✅ Translations complete and base.html regenerated.\")

if __name__ == '__main__':
    perform_translation()
'''

            with open(os.path.join(srv_path, "translator.py"), "w", encoding="utf-8") as tf:
                tf.write(trans_py)

            # --------------------------------------------------------------------------- #
            # 3.d) Write app/__init__.py (fully updated)                                  #
            # --------------------------------------------------------------------------- #
            app_pkg = os.path.join(srv_path, "app")
            os.makedirs(app_pkg, exist_ok=True)

            init_py = '''"""
app/__init__.py  –  FULL FILE
"""

import os
from flask import Flask, render_template, request
from argostranslate import translate as _argos


# --------------------------------------------------------------------------- #
# helper: map folder name (“french”) → Argos Language object (“fr”)           #
# --------------------------------------------------------------------------- #
def _folder_to_lang_obj(folder_name: str):
    folder_name = folder_name.lower()
    for lang in _argos.get_installed_languages():
        if lang.name.lower() == folder_name or lang.code.lower() == folder_name:
            return lang
    return None


def _translate_label(target_folder: str, sentence: str = "Select a Language") -> str:
    """
    Translate *sentence* (assumed English) into the language represented by the
    templates sub‑folder *target_folder* (“spanish”, “fr”, …).
    If no model is installed yet, fall back to the English text.
    """
    src_lang = _folder_to_lang_obj("en")  # src always EN
    dst_lang = _folder_to_lang_obj(target_folder)

    if not src_lang or not dst_lang:
        return sentence  # graceful fallback

    try:
        translation = src_lang.get_translation(dst_lang)
        return translation.translate(sentence)
    except Exception:
        return sentence


# --------------------------------------------------------------------------- #
# main factory                                                                #
# --------------------------------------------------------------------------- #
def create_app():
    pkg_dir       = os.path.dirname(__file__)
    project_root  = os.path.abspath(os.path.join(pkg_dir, ".."))
    templates_dir = os.path.join(project_root, "templates")

    # ----------------------------------------------------------------------- #
    # Flask core                                                              #
    # ----------------------------------------------------------------------- #
    app = Flask(__name__, template_folder=templates_dir)
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.jinja_env.auto_reload = True

    # no‑cache headers so NGINX never stores HTML --------------------------- #
    @app.after_request
    def _no_cache(resp):
        if resp.content_type.startswith("text/html"):
            resp.headers["Cache-Control"] = "no-store, private, must-revalidate"
            resp.headers["Pragma"]        = "no-cache"
            resp.headers["Expires"]       = "0"
        return resp

    # inject languages + translated selector label ------------------------- #
    @app.context_processor
    def inject_languages():
        langs = [
            name for name in os.listdir(templates_dir)
            if os.path.isdir(os.path.join(templates_dir, name))
        ]

        lang_folder = request.view_args.get("lang") if request.view_args else None
        if not lang_folder or lang_folder not in langs:
            lang_folder = "en"

        # map folder → human name
        language_names = {}
        for folder in langs:
            lang_obj = _folder_to_lang_obj(folder)
            language_names[folder] = lang_obj.name if lang_obj else folder.capitalize()

        return dict(
            languages               = langs,
            selected_language       = lang_folder,
            selected_language_label = language_names.get(lang_folder, lang_folder.capitalize()),
            select_language_phrase  = _translate_label(lang_folder),
            language_names          = language_names,
        )

    # routes ---------------------------------------------------------------- #
    @app.route("/")
    def index():
        return render_template("index.html", current_template="index.html")

    @app.route("/<lang>/<template>")
    def serve_translation(lang, template):
        if not template.endswith(".html"):
            template += ".html"
        if lang not in os.listdir(templates_dir):
            return f"Language '{lang}' not supported", 404
        return render_template(f"{lang}/{template}", current_template=template)

    return app
'''

            with open(os.path.join(app_pkg, "__init__.py"), "w", encoding="utf-8") as f:
                f.write(init_py)

            # 3.e) Ensure templates/index.html exists (unchanged)
            tpl_dir = os.path.join(srv_path, "templates")
            os.makedirs(tpl_dir, exist_ok=True)
            idx = os.path.join(tpl_dir, "index.html")
            if not os.path.exists(idx):
                with open(idx, "w", encoding="utf-8") as f:
                    f.write(
                        "{% extends 'base.html' %}\\n"
                        "{% block title %}Home{% endblock %}\\n"
                        "{% block content %}<p>Welcome to "
                        + name +
                        "!</p>{% endblock %}\\n"
                    )

            # 3.f) Generate PWA files
            # service-worker.js (absolute minimum, no caching)
            sw_content = """self.addEventListener('install', event => {
  self.skipWaiting();
});
self.addEventListener('fetch', event => {
  event.respondWith(fetch(event.request));
});"""
            with open(os.path.join(srv_path, "service-worker.js"), "w", encoding="utf-8") as swf:
                swf.write(sw_content)

            # static/ with manifest.json, css/, js/
            static_dir = os.path.join(srv_path, "static")
            os.makedirs(os.path.join(static_dir, "css"), exist_ok=True)
            os.makedirs(os.path.join(static_dir, "js"), exist_ok=True)

            manifest = {
                "name": name,
                "short_name": name,
                "start_url": ".",
                "display": "standalone",
                "background_color": "#ffffff",
                "description": f"{name} PWA",
                "icons": []
            }
            with open(os.path.join(static_dir, "manifest.json"), "w", encoding="utf-8") as mf:
                json.dump(manifest, mf, indent=2)

            # ── 4) Log & refresh GUI ─────────────────────────────────────────
            msg = f"Scaffolded '{name}' on port {main_port}"
            if wants_translator:
                msg += f" (+ translator on port {main_port + 1000})"
            self.gui_events_logger.info(msg)

            # Add to branch manager & inject a new tab immediately
            self.main_branch_manager.add_server(name)
            fr = tk.Frame(self.tab_contents_frame)
            self.tab_frames[name] = fr
            self.tab_order.append(name)
            # False = no SSL by default; adjust if you detect it from cert files
            self.main_branch_manager.create_server_buttons(fr, name, main_port, False)
            self.draw_tab_buttons()
            self.show_tab(name)

        except Exception as exc:
            self.gui_events_logger.error(f"Failed to add server '{name}': {exc}")
            from tkinter import messagebox
            messagebox.showerror("Error Adding Server", str(exc))

    #-----------------------
    # 2.11 UPDATE-NODE TOGGLE
    #-----------------------
    def toggle_update_mode(self) -> None:
        val = self.update_mode_var.get()
        set_config_value(CONFIG_PATH, "update_sending_mode", val)

        mode_str = "ENABLED" if val else "DISABLED"
        self.gui_events_logger.info(f"Update-Sending Mode toggled: {mode_str}")

        if val:
            self.start_update_node_server()
            self.nginx_manager.generate_conf()
        else:
            self.stop_update_node_server()

        self.nginx_manager.reload_conf()

    def start_cert_runtime_log(self):
        log_folder = ensure_log_folder("Self", "CertRuntime")
        self._cert_runtime_log_file = log_folder / "session.log"

        if self._cert_runtime_log_file.exists():
            try:
                self._cert_runtime_log_file.unlink()
            except PermissionError:
                self.gui_events_logger.warning(
                    "Could not delete old session.log (still in use) — appending instead."
                )

        self.cert_logger = get_cert_runtime_logger()
        self.log_cert_runtime_event("Started new cert runtime session")

    def schedule_cert_log_entry(self):
        def check_and_write():
            now = datetime.now()
            # Write timestamp entry
            self.log_cert_runtime_event()

            # Read all timestamps from the log file
            # We'll only parse lines that are strictly timestamps (no event)
            timestamps = []
            try:
                with open(self._cert_runtime_log_file, "r", encoding="utf-8") as f:
                    for line in f:
                        parts = line.strip().split('|')
                        if len(parts) == 2:
                            # It's a plain timestamp line
                            date_str = parts[0].strip()  # e.g. "July 13, 2025"
                            time_str = parts[1].strip()  # e.g. "17:42:08.021"
                            dt = datetime.strptime(f"{date_str} {time_str}", "%B %d, %Y %H:%M:%S.%f")
                            timestamps.append(dt)
            except Exception:
                pass

            if timestamps and (now - timestamps[0]).days >= 90:
                self.log_cert_runtime_event("90 calendar days runtime reached → renewing certs...")
                self.nginx_manager.ensure_all_certificates()
                self.nginx_manager.reload_conf()
                self.log_cert_runtime_event("Cert log reset after renewal")
            self.after(86_400_000, self.schedule_cert_log_entry)

        threading.Thread(target=check_and_write, daemon=True).start()


    def stop_cert_runtime_log(self):
        if hasattr(self, "cert_logger"):
            for h in list(self.cert_logger.handlers):
                try:
                    h.close()
                except Exception:
                    pass
                self.cert_logger.removeHandler(h)
            self.cert_logger = None

        if hasattr(self, "_cert_runtime_log_file") and self._cert_runtime_log_file.exists():
            try:
                self._cert_runtime_log_file.unlink()
            except PermissionError:
                self.gui_events_logger.warning(
                    "Could not delete session.log on shutdown (still in use)."
                )
            except Exception as e:
                self.gui_events_logger.error(f"Error deleting session.log: {e}")

    def start_update_node_server(self):
        if getattr(self, "_update_node_proc", None) and self._update_node_proc.poll() is None:
            return

        exe = sys.executable
        cmd = [exe, "--update-node"]

        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS

        self._update_node_proc = subprocess.Popen(
            cmd,
            cwd=os.path.dirname(exe),
            creationflags=creationflags,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        self.gui_events_logger.info("Update-Node server started (port 5001)")

    def stop_update_node_server(self, *, timeout: float = 5.0) -> None:
        proc = getattr(self, "_update_node_proc", None)
        if proc is None:
            return

        try:
            requests.post("http://127.0.0.1:5001/__shutdown", timeout=2)
        except Exception:
            pass

        deadline = time.time() + timeout
        while time.time() < deadline:
            if proc.poll() is not None:
                break
            time.sleep(0.10)

        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

        self._update_node_proc = None
        self.nginx_manager.generate_conf()
        self.gui_events_logger.info("Update-Node server stopped.")

    def is_port_in_use(self, port: int) -> bool:
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            return s.connect_ex(("127.0.0.1", port)) == 0

    #-----------------------
    # 2.X FIT TO CONTENT
    #-----------------------
    def fit_to_content(self):
        self.update_idletasks()
        prev = self.active_tab
        btns      = self.tab_buttons_frame.winfo_children()
        tab_w     = sum(b.winfo_reqwidth() for b in btns)
        inter     = 4 * len(btns)
        outer     = 20
        total_tab = tab_w + inter + outer
        tab_h     = self.tab_buttons_frame.winfo_reqheight()
        add_h  = getattr(self, "add_server_frame", self.tab_buttons_frame).winfo_reqheight()
        stat_h = 0
        max_w = 0
        max_h = 0
        for key, frame in self.tab_frames.items():
            shown = (key == prev)
            if not shown:
                frame.pack(fill=tk.BOTH, expand=True)
            self.update_idletasks()
            w = frame.winfo_reqwidth()
            h = frame.winfo_reqheight()
            for child in frame.winfo_children():
                if isinstance(child, ttk.Notebook) or isinstance(child, scrolledtext.ScrolledText):
                    w -= child.winfo_reqwidth()
            max_w = max(max_w, w)
            max_h = max(max_h, h)
            if not shown:
                frame.pack_forget()
        if prev in self.tab_frames:
            self.tab_frames[prev].pack(fill=tk.BOTH, expand=True)
        final_w = max(total_tab, max_w)
        final_h = tab_h + add_h + stat_h + max_h
        self.geometry(f"{final_w}x{final_h}")
        self.minsize(final_w, final_h)

    #-----------------------
    # 2.12 WINDOW CLOSE
    #-----------------------
    def on_close(self):
        self.gui_events_logger.info("Server Manager GUI shutting down.")
        self.stop_cert_runtime_log()
        self.destroy()
        try:
            self.quit()
        except Exception:
            pass
