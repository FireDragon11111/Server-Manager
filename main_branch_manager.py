"""
File: server_manager/main_branch_manager.py
-------------------------------------------
Handles main branch server operations, including detection, starting, stopping, and restarting servers, along with associated GUI elements.

TABLE OF CONTENTS
-----------------
1. Imports
2. MainBranchManager Class Definition
   2.1 Initialization
   2.2 Ensure Directories
   2.3 Detect Servers
   2.4 Start Server
   2.5 Stop Server
   2.6 Restart Server
   2.7 Add Server
   2.8 Create GUI Components
   2.9 Populate GUI Widgets
   2.10 Create Server Buttons in GUI
   2.11 View Server Website
   2.12 View Files in Notepad++
   2.13 Open Uploads Folder
   2.14 Log Messages
   2.15 Update Button States
   2.16 Button State Management
   2.17 Package and Send Update
   2.18 Download Files from Server
   2.19 Create Test Branch
3. Helper Methods
"""

#=======================
# 1. IMPORTS
#=======================
import os
import subprocess
import psutil
import socket
import time
import threading
import queue
import shutil
import re
from typing import Any
from collections import defaultdict
from tkinter import ttk, Canvas, messagebox, scrolledtext
import tkinter as tk
from tkinter.ttk import Notebook
from utils import (
    is_port_in_use, allocate_port_for_server, close_open_files, get_root_dir,
    gather_files_to_open, open_browser_window, load_server_config, CONFIG_PATH, StateTracker, CERTBOT_LIVE_DIR, ToolTip, resource_path, get_logger, get_config_value, set_config_value
)
from update_and_receive import UpdateAndReceive

#=======================
# 2. MAINBRANCHMANAGER CLASS DEFINITION
#=======================
class MainBranchManager:
    #-----------------------
    # 2.1 INITIALIZATION
    #-----------------------
    def __init__(self, gui):
        self.events_logger = get_logger("Self", "Main_Branch_Events")
        self.gui                = gui
        self.server_processes   = {}
        self.output_queues      = {}
        self.widget_map: dict[str, dict[str, Any]] = {}
        self.servers            = []
        self.backups_dir            = os.path.join(get_root_dir(), "backups")
        self.certbot_path           = CERTBOT_LIVE_DIR
        self.notepad_plus_plus_path = get_config_value(CONFIG_PATH, "notepad_path", r"D:\Notepad++\notepad++.exe")
        self.exclude_dirs           = ['migrations', '__pycache__', 'venv', 'env']
        self.exclude_patterns       = ['*.pyc', 'env.py']
        self.state_tracker = StateTracker()
        self.parent_frame  = None
        self.servers_frame = None
        self.ensure_directories()
        self.detect_servers(prime_only=True)
        self.update_and_receive = UpdateAndReceive(self)
        for name, _, ssl in self.servers:
            self.update_and_receive.add_server(name, ssl_enabled=ssl)
        self.update_and_receive.register_with_update_node()
        self.log_message("MainBranchManager initialized.", "Init")

    def initialize_gui(self):
        if not hasattr(self.gui, "main_frame") or not self.gui.main_frame:
            self.log_message("[ERROR - initialize_gui] main_frame not found in GUI.", level="error")
            return

        if not self.servers:
            self.detect_servers()

        if self.servers_frame is None:
            self.create_gui(self.gui.main_frame)
        else:
            self.log_message("[DEBUG - initialize_gui] servers_frame already initialized. Skipping.", level="warning")

    def reset_gui_on_startup(self):
        self.gui_initialized = False

        if self.servers_frame and self.servers_frame.winfo_exists():
            for widget in self.servers_frame.winfo_children():
                widget.destroy()
            self.servers_frame.destroy()
            self.servers_frame = None

        self.servers = []
        self.initialize_gui()
        self.log_message("GUI reset and servers re-detected.", "Init")

    #-----------------------
    # 2.2 ENSURE DIRECTORIES
    #-----------------------
    def ensure_directories(self):
        import os, shutil, threading, traceback

        # Determine project root
        root_dir = get_root_dir()

        # 1) Ensure backups, nginx logs, and nginx conf directories exist
        os.makedirs(self.backups_dir, exist_ok=True)
        nginx_logs_dir = os.path.join(root_dir, "nginx", "logs")
        nginx_conf_dir = os.path.join(root_dir, "nginx", "conf")
        os.makedirs(nginx_logs_dir, exist_ok=True)
        os.makedirs(nginx_conf_dir, exist_ok=True)

        # 2) Compute stray nginx folder path one level above project root
        parent_root = os.path.abspath(os.path.join(root_dir, os.pardir))
        orphan_nginx = os.path.join(parent_root, "nginx")

        # 3) If it exists, log its contents and attempt removal
        if os.path.isdir(orphan_nginx):
            try:
                contents = os.listdir(orphan_nginx)
                self.log_message(
                    f"[ensure_directories] Orphan nginx folder contents: {contents}",
                    "Main",
                    level="warning"
                )
            except Exception as e:
                self.log_message(
                    f"[ensure_directories] Could not list orphan nginx folder: {e}",
                    "Main",
                    level="warning"
                )

            try:
                shutil.rmtree(orphan_nginx)
                self.log_message(
                    "[ensure_directories] Removed stray nginx folder at project root.",
                    "Main"
                )
            except Exception as e:
                self.log_message(
                    f"[ensure_directories] Failed to remove orphan nginx folder: {e}",
                    "Main",
                    level="error"
                )
        else:
            self.log_message(
                "[ensure_directories] No stray nginx folder found at project root to remove.",
                "Main"
            )

    # ── 2.3 DETECT SERVERS ─────────────────────────────────────────────
    def detect_servers(self, *, prime_only: bool = False) -> None:
        self.servers.clear()
        cfg  = load_server_config(CONFIG_PATH)
        root = get_root_dir()

        for folder in os.listdir(root):
            if (
                folder.startswith("testing.") or
                folder in {"Server Manager", "Update Node Server"} or
                not os.path.isdir(os.path.join(root, folder)) or
                not os.path.isfile(os.path.join(root, folder, "main.py"))
            ):
                continue

            port = cfg["servers"].get(folder) or allocate_port_for_server(folder)
            cert_dir    = os.path.join(self.certbot_path, folder)
            ssl_enabled = (
                os.path.isfile(os.path.join(cert_dir, "fullchain.pem")) and
                os.path.isfile(os.path.join(cert_dir, "privkey.pem"))
            )

            self.servers.append((folder, port, ssl_enabled))
            self.log_message(
                f"Detected server ‘{folder}’ on port {port}  (SSL: {ssl_enabled})",
                "Main"
            )

            if not prime_only and hasattr(self, "update_and_receive"):
                self.update_and_receive.add_server(folder, ssl_enabled=ssl_enabled)

        if (not prime_only) and hasattr(self.gui, "nginx_manager"):
            self.gui.nginx_manager.generate_conf()

        if (not prime_only) and hasattr(self, "update_and_receive"):
            self.update_and_receive.register_with_update_node()

        self.update_button_states()

    def _setup_log_tabs(self, server_name, notebook):
        server_root = os.path.join(get_root_dir(), server_name)
        logs_dir = os.path.join(server_root, "logs")
        if not os.path.exists(logs_dir):
            frame = ttk.Frame(notebook)
            txt = scrolledtext.ScrolledText(frame, state='disabled', height=8)
            txt.insert(tk.END, "No logs found.")
            txt.pack(fill=tk.BOTH, expand=True)
            notebook.add(frame, text="Logs")
            return

        log_sources = self._detect_latest_logs(logs_dir)
        self._log_widgets = getattr(self, "_log_widgets", {})
        self._log_widgets[server_name] = {}

        for category, log_path in log_sources.items():
            frame = ttk.Frame(notebook)
            txt = scrolledtext.ScrolledText(frame, state='disabled', height=8, font=("Consolas", 9))
            txt.pack(fill=tk.BOTH, expand=True)
            notebook.add(frame, text=category)
            self._log_widgets[server_name][category] = txt

            threading.Thread(
                target=self._follow_log_file,
                args=(txt, log_path),
                daemon=True
            ).start()

    def _detect_latest_logs(self, logs_root):
        log_paths = {}
        date_suffix_pattern = re.compile(r"^(.*?)[-_]?\d{4}-\d{2}-\d{2}\.log$", re.IGNORECASE)
        grouped_logs = defaultdict(list)

        for entry in os.listdir(logs_root):
            full_path = os.path.join(logs_root, entry)

            if os.path.isdir(full_path):
                # Treat directory as a category
                log_files = [os.path.join(full_path, f) for f in os.listdir(full_path) if f.endswith(".log")]
                if log_files:
                    latest = max(log_files, key=os.path.getmtime)
                    pretty_name = re.sub(r'[_-]+', ' ', entry).strip().title()
                    log_paths[pretty_name] = latest

            elif entry.endswith(".log"):
                match = date_suffix_pattern.match(entry)
                if match:
                    raw_name = match.group(1)
                else:
                    raw_name = entry.rsplit(".", 1)[0]

                cleaned = re.sub(r'^(log[-_]?|logs[-_]?)', '', raw_name, flags=re.IGNORECASE)
                grouped_logs[cleaned].append(full_path)

        for raw_group, files in grouped_logs.items():
            latest = max(files, key=os.path.getmtime)
            pretty_name = re.sub(r'[_-]+', ' ', raw_group).strip().title()
            log_paths[pretty_name] = latest

        return log_paths

    def _follow_log_file(self, widget, file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.3)
                        continue
                    widget.after(0, self._append_log_line, widget, line.strip())
        except Exception as e:
            self.log_message(f"Error reading log file {file_path}: {e}", "Main", level="error")

    def _append_log_line(self, widget, message):
        widget.config(state='normal')
        widget.insert(tk.END, message + "\n")
        widget.see(tk.END)
        widget.config(state='disabled')

    def download_current_files_from_server(self, server_name):
        self.log_message(f"[UI] Download Current Files from Remote pressed for server: {server_name}", "Main")
        handler = self.update_and_receive.update_handlers.get(server_name)
        if handler:
            handler.safe_log(f"[MainBranchManager] Initiating pull request for {server_name}", "Update")
            handler.pull_current_files()
            fn = handler._get_latest()
            if fn:
                handler.safe_log(f"[MainBranchManager] Forcing download of {fn}", "Update")
                handler.download(fn)
            else:
                self.log_message(f"No updates found to download for {server_name}.", "Main")
        else:
            self.log_message(f"No UpdateHandler found for {server_name}.", "Main")
    download_files_from_server = download_current_files_from_server

    #-----------------------
    # 2.4 START SERVER
    #-----------------------
    def start_server(self, server_name, port, app_directory):
        if self.is_waitress_running(server_name):
            self.log_message(f"Server {server_name} is already running.", "Main")
            return

        command = [
            "python", "-m", "waitress",
            f"--listen=127.0.0.1:{port}",
            "--threads=8",
            "--call", "main:create_app"
        ]
        try:
            process = subprocess.Popen(
                command,
                cwd=app_directory,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True,
                creationflags=(
                    subprocess.DETACHED_PROCESS |
                    subprocess.CREATE_NEW_PROCESS_GROUP
                )
            )
            self.server_processes[server_name] = process
            self.output_queues[server_name] = queue.Queue()

            threading.Thread(
                target=self.enqueue_output,
                args=(process.stdout, server_name),
                daemon=True
            ).start()
            threading.Thread(
                target=self.enqueue_output,
                args=(process.stderr, server_name),
                daemon=True
            ).start()
            threading.Thread(
                target=self.process_output,
                args=(server_name,),
                daemon=True
            ).start()

            self.log_message(f"{server_name} (Port {port}) started.", "Main")
            self.update_gui_elements(server_name, running=True)
            running = get_config_value(CONFIG_PATH, "running_servers", [])
            if server_name not in running:
                running.append(server_name)
                set_config_value(CONFIG_PATH, "running_servers", running)

        except Exception as e:
            self.log_message(f"Failed to start {server_name}: {e}", "Main")


    def stop_server(self, server_name):
        port = self.get_port_by_server_name(server_name)
        if not port:
            self.log_message(f"No port found for {server_name}.", "Main")
            return

        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr.port == port and conn.status == psutil.CONN_LISTEN:
                    proc = psutil.Process(conn.pid)
                    proc.terminate()
                    proc.wait(timeout=5)
                    self.log_message(
                        f"Stopped server {server_name} on port {port}.",
                        "Main"
                    )
                    self.update_gui_elements(server_name, running=False)
                    running = get_config_value(
                        CONFIG_PATH, "running_servers", []
                    )
                    if server_name in running:
                        running.remove(server_name)
                        set_config_value(
                            CONFIG_PATH, "running_servers", running
                        )
                    break

        except Exception as e:
            self.log_message(f"Error stopping {server_name}: {e}", "Main")

    def is_translator_running(self, server_name: str) -> bool:
        """Check if the translation server (main_port+1000) is listening or its process is alive."""
        key = f"{server_name}_translator"
        if key in self.server_processes and self.server_processes[key].poll() is None:
            return True
        main_port = self.get_port_by_server_name(server_name)
        if not main_port:
            return False
        trans_port = main_port + 1000
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr.port == trans_port and conn.status == psutil.CONN_LISTEN:
                return True
        return False

    def start_translation_server(self, server_name: str):
        """Launch a waitress-backed Argos-Translate microservice on port=main_port+1000, without a visible console window."""
        main_port = self.get_port_by_server_name(server_name)
        if not main_port:
            self.log_message(f"No main port for {server_name}. Cannot start translator.", "Main")
            return
        trans_port = main_port + 1000
        if self.is_translator_running(server_name):
            self.log_message(f"Translation server already running for {server_name}.", "Main")
            return

        app_dir = os.path.join(get_root_dir(), server_name)
        cmd = [
            "python", "-m", "waitress",
            f"--listen=127.0.0.1:{trans_port}",
            "--threads=8",
            "--call", "translator:create_app"
        ]

        # ─── Hide console window on Windows ───────────────────────
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = subprocess.SW_HIDE

        proc = subprocess.Popen(
            cmd,
            cwd=app_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            startupinfo=si,  # suppress the console window
        )

        # keep track under a distinct key
        key = f"{server_name}_translator"
        self.server_processes[key] = proc
        self.output_queues[key] = queue.Queue()

        threading.Thread(
            target=self.enqueue_output,
            args=(proc.stdout, key),
            daemon=True
        ).start()
        threading.Thread(
            target=self.enqueue_output,
            args=(proc.stderr, key),
            daemon=True
        ).start()

        self.log_message(f"Started translation server for {server_name} on port {trans_port}.", "Main")

    def stop_translation_server(self, server_name: str):
        """Terminate the translation server process listening on main_port+1000."""
        key = f"{server_name}_translator"
        proc = self.server_processes.get(key)

        # 1) Try to terminate the tracked subprocess directly
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except psutil.TimeoutExpired:
                proc.kill()
            self.log_message(f"Stopped translation server for {server_name}.", "Main")
            # Clean up our bookkeeping
            del self.server_processes[key]
            self.output_queues.pop(key, None)
            return

        # 2) Fallback: scan for a LISTEN on main_port+1000
        main_port = self.get_port_by_server_name(server_name)
        if not main_port:
            self.log_message(f"No main port for {server_name}. Cannot stop translator.", "Main")
            return
        trans_port = main_port + 1000

        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr.port == trans_port and conn.status == psutil.CONN_LISTEN:
                try:
                    p = psutil.Process(conn.pid)
                    p.terminate()
                    try:
                        p.wait(timeout=5)
                    except psutil.TimeoutExpired:
                        p.kill()
                    self.log_message(f"Stopped translation server for {server_name} on port {trans_port}.", "Main")
                except Exception as e:
                    self.log_message(f"Error stopping translation server for {server_name}: {e}", "Main", level="error")
                return

        self.log_message(f"No translation server running for {server_name}.", "Main")

    def restart_translation_server(self, server_name: str):
        """Restart the translation server (stop then start)."""
        self.stop_translation_server(server_name)
        time.sleep(1)
        self.start_translation_server(server_name)

    #-----------------------
    # 2.6 RESTART SERVER
    #-----------------------
    def restart_server(self, server_name, port, app_directory):
        self.stop_server(server_name)
        time.sleep(1)
        self.start_server(server_name, port, app_directory)

    #-----------------------
    # 2.7 ADD SERVER
    #-----------------------
    def add_server(self, server_name: str) -> None:
        root        = get_root_dir()
        folder_path = os.path.join(root, server_name)

        if not os.path.isdir(folder_path):
            self.log_message(f"Invalid server directory: {folder_path}", "Main")
            return

        port = allocate_port_for_server(server_name)

        cert_dir     = os.path.join(self.certbot_path, server_name)
        ssl_enabled  = (
            os.path.isfile(os.path.join(cert_dir, "fullchain.pem")) and
            os.path.isfile(os.path.join(cert_dir, "privkey.pem"))
        )

        self.servers.append((server_name, port, ssl_enabled))
        self.log_message(
            f"Added server ‘{server_name}’ on port {port}  (SSL: {ssl_enabled})",
            "Main"
        )

        self.update_and_receive.add_server(server_name, ssl_enabled=ssl_enabled)

        threading.Thread(
            target=lambda: (
                self.gui.nginx_manager.generate_conf(),
                self.gui.nginx_manager.reload_conf()
            ),
            daemon=True
        ).start()

        self.update_button_states()
        self.update_and_receive.register_with_update_node()

    #-----------------------
    # 2.8 CREATE GUI COMPONENTS
    #-----------------------
    def create_gui(self, parent):
        if not parent:
            self.log_message("[ERROR - create_gui] Parent frame is missing. Cannot create Main Branch Servers frame.", level="error")
            return

        if self.servers_frame and self.servers_frame.winfo_exists():
            for widget in self.servers_frame.winfo_children():
                widget.destroy()
            self.servers_frame.destroy()

        self.servers_frame = ttk.LabelFrame(parent, text="Main Branch Servers")
        self.servers_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.detect_servers()
        self._populate_gui_widgets(self.servers_frame)

    #-----------------------
    # 2.9 POPULATE GUI WIDGETS
    #-----------------------
    def _populate_gui_widgets(self, frame):
        self.widget_map.clear()
        retained_widgets = {}
        for widget in frame.winfo_children():
            if isinstance(widget, scrolledtext.ScrolledText):
                server_name = getattr(widget, "server_name", None)
                if server_name:
                    retained_widgets[server_name] = widget.get("1.0", tk.END)

        for widget in frame.winfo_children():
            if isinstance(widget, scrolledtext.ScrolledText):
                continue
            widget.destroy()

        self.detect_servers()

        for server_name, port, ssl in self.servers:
            self.create_server_buttons(frame, server_name, port, ssl)
            if server_name in retained_widgets:
                log_widget = getattr(self, f"{server_name}_log_area", None)
                if log_widget:
                    log_widget.delete("1.0", tk.END)
                    log_widget.insert(tk.END, retained_widgets[server_name])
        self.update_button_states()

    #-----------------------
    # 2.10 CREATE SERVER BUTTONS IN GUI
    #-----------------------
    def create_server_buttons(self, parent, server_name, port, ssl):
        from PIL import Image, ImageTk
        from utils import resource_path, get_root_dir
        import os
        import tkinter as tk
        from tkinter import Canvas
        from tkinter import ttk
        from utils import ToolTip  # assuming ToolTip lives in utils

        def load_icon(filename, size=(16, 16)):
            path = resource_path(f"assets/{filename}")
            img = Image.open(path).resize(size, Image.LANCZOS)
            return ImageTk.PhotoImage(img)

        def add_btn(parent, key, command, tooltip_text):
            btn = ttk.Button(parent, image=icons[key], width=3, command=command)
            btn.image = icons[key]
            btn.pack(side=tk.LEFT, padx=2)
            tt = ToolTip(btn, tooltip_text)
            return btn, tt

        # ─── Containers ──────────────────────────────────────────────
        row_frame = ttk.Frame(parent)
        row_frame.pack(fill=tk.X, pady=2)

        header = ttk.Frame(row_frame)
        header.pack(fill=tk.X, pady=(0, 4))
        status_dot = Canvas(header, width=20, height=20, highlightthickness=0)
        status_dot.pack(side=tk.LEFT)
        dot_id = status_dot.create_oval(
            2, 2, 18, 18,
            fill="green" if self.is_waitress_running(server_name) else "red",
            outline=""
        )

        label_frame = ttk.Frame(header)
        label_frame.pack(side=tk.LEFT, padx=5)
        ttk.Label(label_frame, text=server_name, font=("Segoe UI", 11, "bold")).pack(anchor="w")
        meta = ttk.Frame(label_frame)
        meta.pack(anchor="w")
        ttk.Label(meta, text=f"Port: {port}", font=("Segoe UI", 9)).pack(side=tk.LEFT)
        ttk.Label(meta, text="   " + ("[SSL]" if ssl else "[No SSL]"), font=("Segoe UI", 9)).pack(side=tk.LEFT)

        # ─── Icons ───────────────────────────────────────────────────
        icon_row = ttk.Frame(row_frame)
        icon_row.pack(fill=tk.X, pady=(0, 5))
        icons = {
            "start":     load_icon("Play Icon.png"),
            "stop":      load_icon("Stop Icon.png"),
            "restart":   load_icon("Restart Icon.png"),
            "files":     load_icon("View Files Icon.png"),
            "site":      load_icon("View Site Icon.png"),
            "send":      load_icon("Package & Send Updates Icon.png"),
            "pull":      load_icon("Download Updates Icon.png"),
            "test":      load_icon("Create New Test Branch Icon.png"),
#            "translate": load_icon("Translation Server Icon.png"),
            "server": load_icon("Server Icon.png"),
        }

        # ─── Command closures ────────────────────────────────────────
        def _on_start():
            self.start_server(server_name, port, os.path.join(get_root_dir(), server_name))
            self.update_gui_elements(server_name, True)
            self.gui.draw_tab_buttons(); self.gui.update_status_row()

        def _on_stop():
            self.stop_server(server_name)
            self.update_gui_elements(server_name, False)
            self.gui.draw_tab_buttons(); self.gui.update_status_row()

        def _on_restart():
            self.restart_server(server_name, port, os.path.join(get_root_dir(), server_name))
            running = self.is_waitress_running(server_name)
            self.update_gui_elements(server_name, running)
            self.gui.draw_tab_buttons(); self.gui.update_status_row()

        # def _on_translate_start():
            # self.start_translation_server(server_name)
            # # disable “Start”, enable “Stop”
            # btn_trans_start.config(state=tk.DISABLED)
            # btn_trans_stop .config(state=tk.NORMAL)
            # self.gui.draw_tab_buttons()
            # self.gui.update_status_row()

        # def _on_translate_stop():
            # self.stop_translation_server(server_name)
            # # enable “Start”, disable “Stop”
            # btn_trans_start.config(state=tk.NORMAL)
            # btn_trans_stop .config(state=tk.DISABLED)
            # self.gui.draw_tab_buttons()
            # self.gui.update_status_row()

        # def _on_translate_restart():
            # self.restart_translation_server(server_name)
            # # after restart it’s running
            # btn_trans_start.config(state=tk.DISABLED)
            # btn_trans_stop .config(state=tk.NORMAL)
            # self.gui.draw_tab_buttons()
            # self.gui.update_status_row()

        # ─── Build buttons ───────────────────────────────────────────
        # Static “row icon”
        static_icon = ttk.Label(icon_row, image=icons["server"])
        static_icon.image = icons["server"]
        static_icon.pack(side=tk.LEFT, padx=(2, 4))
        btn_start,   tt_start   = add_btn(icon_row, "start",     _on_start,     "Start Server")
        btn_stop,    tt_stop    = add_btn(icon_row, "stop",      _on_stop,      "Stop Server")
        btn_restart, tt_restart = add_btn(icon_row, "restart",   _on_restart,   "Restart Server")
        ttk.Label(icon_row, text="|").pack(side=tk.LEFT, padx=4)
        add_btn(icon_row, "files",   lambda: self.view_files(server_name),       "View Server Files")
        add_btn(icon_row, "site",    lambda: self.view_site(server_name),        "Open Website in Browser")
        ttk.Label(icon_row, text="|").pack(side=tk.LEFT, padx=4)
        add_btn(icon_row, "send",    lambda: self.package_and_send(server_name), "Package & Send Current Files")
        add_btn(icon_row, "pull",    lambda: self.download_current_files_from_server(server_name), "Download Current Files from Remote")
        ttk.Label(icon_row, text="|").pack(side=tk.LEFT, padx=4)
        add_btn(icon_row, "test",    lambda: self.create_test_branch(server_name), "Create Test Branch")

        # # ─── Translation Server Controls ─────────────────────────────
        # trans_row = ttk.Frame(row_frame)
        # trans_row.pack(fill=tk.X, pady=(0, 5))

        # # Static “row icon”
        # static_icon = ttk.Label(trans_row, image=icons["translate"])
        # static_icon.image = icons["translate"]
        # static_icon.pack(side=tk.LEFT, padx=(2, 4))

        # # Translation control buttons
        # trans_running = self.is_translator_running(server_name)

        # btn_trans_start, tt_trans_start = add_btn(
            # trans_row, "start", _on_translate_start, "Start Translation Server"
        # )
        # btn_trans_stop, tt_trans_stop   = add_btn(
            # trans_row, "stop",  _on_translate_stop,  "Stop Translation Server"
        # )
        # btn_trans_restart, tt_trans_restart = add_btn(
            # trans_row, "restart", _on_translate_restart, "Restart Translation Server"
        # )

        # # Initial enable/disable based on current state
        # btn_trans_start.config(state=tk.DISABLED if trans_running else tk.NORMAL)
        # btn_trans_stop .config(state=tk.NORMAL   if trans_running else tk.DISABLED)
        # # (Restart always enabled)

        # ─── Store widgets for updates ────────────────────────────────
        self.widget_map[server_name] = {
            "status_dot":        status_dot,
            "oval_id":           dot_id,
            "btn_start":         btn_start,
            "btn_stop":          btn_stop,
            # "btn_trans_start":   btn_trans_start,
            # "btn_trans_stop":    btn_trans_stop,
            # "btn_trans_restart": btn_trans_restart,
        }

        # ─── Initialize main controls ────────────────────────────────
        running = self.is_waitress_running(server_name)
        btn_start.config(state=tk.DISABLED if running else tk.NORMAL)
        btn_stop .config(state=tk.NORMAL   if running else tk.DISABLED)

        # ─── Logging tabs ────────────────────────────────────────────
        log_tabs = ttk.Notebook(parent)
        log_tabs.pack(fill=tk.BOTH, expand=True, pady=2)
        setattr(self, f"{server_name}_log_tabs", log_tabs)
        self._setup_log_tabs(server_name, log_tabs)

    def package_and_send(self, server_name):
        handler = self.update_and_receive.update_handlers.get(server_name)
        if handler:
            handler.package_and_send()
        else:
            self.log_message(f"No UpdateHandler found for {server_name}.", "Main")

    def download_files_from_server(self, server_name):
        handler = self.update_and_receive.update_handlers.get(server_name)
        if handler:
            handler.fetch_updates()
        else:
            self.log_message(f"No UpdateHandler found for {server_name}.", "Main")

    #-----------------------
    # 2.11 VIEW SERVER WEBSITE
    #-----------------------
    def view_site(self, server_name):
        port = self.get_port_by_server_name(server_name)
        if port:
            url = f"http://127.0.0.1:{port}"
            try:
                open_browser_window(url, server_name)
                self.log_message(f"Opened browser for {server_name} at {url}.", "Main")
            except Exception as e:
                self.log_message(f"Failed to open browser for {server_name}: {e}", "Main")
        else:
            self.log_message(f"Port not found for {server_name}. Cannot open browser.", "Main")

    #-----------------------
    # 2.12 VIEW FILES IN NOTEPAD++
    #-----------------------
    def view_files(self, server_name):
        server_dir = os.path.join(get_root_dir(), server_name)
        if not os.path.isdir(server_dir):
            self.log_message(f"Server directory does not exist: {server_dir}", "Main")
            return

        if not os.path.exists(self.notepad_plus_plus_path):
            self.log_message("Notepad++ not found. Check config.", "Main")
            return

        files_to_open = gather_files_to_open(server_dir, self.exclude_dirs, self.exclude_patterns, file_extensions=('.py', '.html', '.css', '.js', '.json'))
        if files_to_open:
            try:
                subprocess.Popen([self.notepad_plus_plus_path, '-multiInst', '-nosession'] + files_to_open)
                self.log_message(f"Opened {len(files_to_open)} files for {server_name} in Notepad++.", "Main")
            except Exception as e:
                self.log_message(f"Failed to open files for {server_name}: {e}", "Main")
        else:
            self.log_message(f"No files to open for {server_name}.", "Main")

    #-----------------------
    # 2.13 OPEN UPLOADS FOLDER
    #-----------------------
    def open_uploads_folder(self, uploads_path):
        if os.path.exists(uploads_path):
            try:
                subprocess.Popen(f'explorer "{uploads_path}"')
                self.log_message(f"Opened uploads folder at {uploads_path}.", "Main")
            except Exception as e:
                self.log_message(f"Failed to open uploads folder: {e}", "Main")
        else:
            self.log_message(f"Uploads folder does not exist: {uploads_path}.", "Main")

    #-----------------------
    # 2.14 LOG MESSAGES
    #-----------------------
    def log_message(self, message, category="Main", level="info"):
        timestamp = time.strftime("[%B %d, %Y | %H:%M:%S]")
        full_message = f"{timestamp} [{category}] {message}\n"
        if hasattr(self, "events_logger") and self.events_logger:
            if level == "error":
                self.events_logger.error(message)
            elif level == "warning":
                self.events_logger.warning(message)
            else:
                self.events_logger.info(message)
        self.gui.log_message(full_message, category)

    #-----------------------
    # 2.15 UPDATE BUTTON STATES
    #-----------------------
    def update_button_states(self):
        if not hasattr(self.gui, 'main_frame') or not self.gui.main_frame:
            self.log_message("[ERROR - update_button_states] main_frame is missing. Skipping button state updates.", level="error")
            return

        if not self.servers_frame or not self.servers_frame.winfo_exists():
            self.log_message("[DEBUG - main_branch_manager.py] servers_frame is invalid or destroyed. Skipping update_button_states.", level="warning")
            return

        for server_name, port, _ in self.servers:
            running = self.is_waitress_running(server_name)
            self.update_gui_elements(server_name, running)

    #-----------------------
    # 2.16 BUTTON STATE MANAGEMENT
    #-----------------------
    def enable_start_button (self, srv): self._set_btn_state(srv, "btn_start", tk.NORMAL)
    def disable_start_button(self, srv): self._set_btn_state(srv, "btn_start", tk.DISABLED)
    def enable_stop_button  (self, srv): self._set_btn_state(srv, "btn_stop",  tk.NORMAL)
    def disable_stop_button (self, srv): self._set_btn_state(srv, "btn_stop",  tk.DISABLED)

    def _set_btn_state(self, srv: str, key: str, state):
        w = self.widget_map.get(srv, {}).get(key)
        if w:
            w.config(state=state)

    #-----------------------
    # 2.17 PACKAGE AND SEND UPDATE
    #-----------------------
    def package_and_send(self, server_name):
        handler = self.update_and_receive.update_handlers.get(server_name)
        if handler:
            try:
                handler.package_and_send()
            except Exception as e:
                self.update_and_receive._log_local(f"[{server_name}] ERROR in handler.package_and_send: {e}")
                import traceback
                self.update_and_receive._log_local(traceback.format_exc())
                self.log_message(f"Error packaging/sending update for {server_name}: {e}", "Main")
        else:
            self.log_message(f"No UpdateHandler found for {server_name}.", "Main")

    #-----------------------
    # 2.18 DOWNLOAD FILES FROM SERVER
    #-----------------------
    def download_files_from_server(self, server_name):
        handler = self.update_and_receive.update_handlers.get(server_name)
        if handler:
            handler.fetch_updates()
        else:
            self.log_message(f"No UpdateHandler found for {server_name}.", "Main")

    #-----------------------
    # 2.19 CREATE TEST BRANCH
    #-----------------------
    def create_test_branch(self, server_name):
        source_dir = os.path.join(get_root_dir(), server_name)
        dest_dir = os.path.join(get_root_dir(), f"testing.{server_name}")

        if os.path.exists(source_dir):
            try:
                if os.path.exists(dest_dir):
                    shutil.rmtree(dest_dir)
                shutil.copytree(source_dir, dest_dir)
                self.log_message(f"Created test branch: {dest_dir}", "Main")
                self.gui.test_branch_manager.detect_test_branches()
            except Exception as e:
                self.log_message(f"Failed to create test branch for {server_name}: {e}", "Main")
        else:
            self.log_message(f"Source directory does not exist: {source_dir}", "Main")

    #-----------------------
    # 3. HELPER METHODS
    #-----------------------
    def update_gui_elements(self, server_name: str, running: bool) -> None:
        widgets = self.widget_map.get(server_name)
        if not widgets:        # row not built yet
            return

        colour = "green" if running else "red"
        widgets["status_dot"].itemconfig(widgets["oval_id"], fill=colour)
        widgets["btn_start"].config(state=tk.DISABLED if running else tk.NORMAL)
        widgets["btn_stop"] .config(state=tk.NORMAL   if running else tk.DISABLED)

    def get_all_server_names(self) -> list[str]:
        return [name for name, _, _ in self.servers]

    def get_port_by_server_name(self, server_name):
        for server in self.servers:
            if server[0] == server_name:
                return server[1]
        return None

    def is_waitress_running(self, server_name):
        if server_name in self.server_processes and self.server_processes[server_name].poll() is None:
            return True

        for server in self.servers:
            if server[0] == server_name:
                port = server[1]
                for conn in psutil.net_connections(kind='inet'):
                    if conn.laddr.port == port and conn.status == psutil.CONN_LISTEN:
                        return True

        return False

    def enqueue_output(self, out, server_name):
        for line in iter(out.readline, ''):
            self.output_queues[server_name].put(line)
        out.close()

    def process_output(self, server_name):
        while True:
            try:
                line = self.output_queues[server_name].get(timeout=1)
                log_area = getattr(self, f"{server_name}_log_area", None)
                if log_area:
                    log_area.configure(state='normal')
                    log_area.insert(tk.END, line)
                    log_area.configure(state='disabled')
                    log_area.see(tk.END)
            except queue.Empty:
                if server_name not in self.server_processes or self.server_processes[server_name].poll() is not None:
                    break

