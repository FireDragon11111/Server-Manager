"""
File: server_manager/test_branch_manager.py
--------------------------------------------
Handles test branch server operations, including creation, deployment, deletion, and management, along with associated GUI elements.

TABLE OF CONTENTS
-----------------
1. Imports
2. TestBranchManager Class Definition
   2.1 Initialization
   2.2 Ensure Directories
   2.3 Detect Test Branches
   2.4 Start Test Branch
   2.5 Stop Test Branch
   2.6 Restart Test Branch
   2.7 Deploy Test Branch
   2.8 Delete Test Branch
   2.9 Create GUI Components
   2.10 Populate GUI Widgets
   2.11 Create Test Branch Buttons
   2.12 View Test Branch Website
   2.13 View Test Branch Files
   2.14 Log Messages
   2.15 Update Button States
   2.16 Enqueue and Process Output
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
from collections import defaultdict
from tkinter import ttk, scrolledtext, Canvas, messagebox
import tkinter as tk
from tkinter.ttk import Notebook
from utils import (
    allocate_port_for_server, release_port_for_server, get_root_dir, gather_files_to_open,
    close_open_files, load_server_config, update_server_config, CONFIG_PATH, open_browser_window, ToolTip, resource_path, StateTracker, get_logger, get_config_value, set_config_value
)
from update_and_receive import UpdateAndReceive

#=======================
# 2. TESTBRANCHMANAGER CLASS DEFINITION
#=======================
class TestBranchManager:
    #-----------------------
    # 2.1 INITIALIZATION
    #-----------------------
    def __init__(self, gui):
        self.events_logger = get_logger("Self", "Test_Branch_Events")
        self.gui = gui
        self.test_branch_processes = {}
        self.output_queues = {}
        self.test_branches = []
        self.test_branches_frame = None
        self.backups_dir = os.path.join(get_root_dir(), "backups")
        os.makedirs(self.backups_dir, exist_ok=True)
        self.state_tracker = StateTracker()
        self.notepad_plus_plus_path = get_config_value(CONFIG_PATH, "notepad_path", r"D:\Notepad++\notepad++.exe")
        self.exclude_dirs = ['migrations', '__pycache__', 'venv', 'env']
        self.exclude_patterns = ['*.pyc', 'env.py']
        self.branch_widgets = {}
        self.log_message("TestBranchManager initialized.", "Init")

    def _load_icon(self, path, size=(18, 18)):
        from PIL import Image, ImageTk
        try:
            resolved = resource_path(path)
            image = Image.open(resolved)
            image = image.resize(size, Image.ANTIALIAS)
            return ImageTk.PhotoImage(image)
        except Exception as e:
            self.log_message(f"Failed to load icon {path}: {e}", "Test", level="error")
            return None

    #-----------------------
    # 2.2 ENSURE DIRECTORIES
    #-----------------------
    def ensure_directories(self):
        os.makedirs(self.backups_dir, exist_ok=True)

    #-----------------------
    # 2.3 DETECT TEST BRANCHES
    #-----------------------
    def detect_test_branches(self):
        self.test_branches = []
        config = load_server_config(CONFIG_PATH)

        for folder_name in os.listdir(get_root_dir()):
            if not folder_name.startswith("testing."):
                continue

            folder_path = os.path.join(get_root_dir(), folder_name)
            main_py_path = os.path.join(folder_path, "main.py")
            if os.path.isdir(folder_path) and os.path.exists(main_py_path):
                port = config['servers'].get(folder_name)
                if not port:
                    port = allocate_port_for_server(folder_name)
                    update_server_config(CONFIG_PATH, folder_name, port)

                self.test_branches.append((folder_name, port, False))
                self.log_message(f"Detected test branch: {folder_name} on port {port}.", "Test")
        self.log_message(f"Detected {len(self.test_branches)} test branches.", "Test")

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
            self.log_message(f"Error reading log file: {e}", "Test", level="error")

    def _append_log_line(self, widget, message):
        widget.config(state='normal')
        widget.insert(tk.END, message + "\n")
        widget.see(tk.END)
        widget.config(state='disabled')

    #-----------------------
    # 2.4 START TEST BRANCH
    #-----------------------
    def start_test_branch(self, test_branch_name, port):
        app_directory = os.path.join(get_root_dir(), test_branch_name)
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
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
            )
            self.test_branch_processes[test_branch_name] = process
            self.output_queues[test_branch_name] = queue.Queue()

            threading.Thread(
                target=self.enqueue_output,
                args=(process.stdout, test_branch_name),
                daemon=True
            ).start()
            threading.Thread(
                target=self.enqueue_output,
                args=(process.stderr, test_branch_name),
                daemon=True
            ).start()
            threading.Thread(
                target=self.process_output,
                args=(test_branch_name,),
                daemon=True
            ).start()

            time.sleep(1)
            self.update_button_states()
            self.log_message(f"Started {test_branch_name} on port {port}.", "Test")
            running = get_config_value(CONFIG_PATH, "running_servers", [])
            if test_branch_name not in running:
                running.append(test_branch_name)
                set_config_value(CONFIG_PATH, "running_servers", running)

        except Exception as e:
            self.log_message(f"Failed to start {test_branch_name}: {e}", "Test")


    def stop_test_branch(self, test_branch_name):
        port = self.get_port_by_test_branch_name(test_branch_name)
        if port is None:
            self.log_message(f"No port found for {test_branch_name}.", "Test")
            return
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr.port == port and conn.status == psutil.CONN_LISTEN:
                    if conn.pid:
                        proc = psutil.Process(conn.pid)
                        proc.terminate()
                        proc.wait(timeout=5)
                        self.log_message(
                            f"Stopped {test_branch_name} on port {port}.", 
                            "Test"
                        )
                        running = get_config_value(
                            CONFIG_PATH, "running_servers", []
                        )
                        if test_branch_name in running:
                            running.remove(test_branch_name)
                            set_config_value(
                                CONFIG_PATH, "running_servers", running
                            )
                        break

            time.sleep(1)
            self.update_button_states()

        except Exception as e:
            self.log_message(f"Failed to stop {test_branch_name}: {e}", "Test")

    #-----------------------
    # 2.6 RESTART TEST BRANCH
    #-----------------------
    def restart_test_branch(self, test_branch_name):
        self.stop_test_branch(test_branch_name)
        port = self.get_port_by_test_branch_name(test_branch_name)
        if port:
            self.start_test_branch(test_branch_name, port)

    #-----------------------
    # 2.7 DEPLOY TEST BRANCH
    #-----------------------
    def deploy_test_branch(self, test_branch_name):
        main_branch_name = test_branch_name.replace("testing.", "")
        test_branch_dir = os.path.join(get_root_dir(), test_branch_name)
        main_branch_dir = os.path.join(get_root_dir(), main_branch_name)

        if not os.path.exists(test_branch_dir):
            self.log_message(f"Test Branch directory does not exist: {test_branch_dir}", "Test")
            return

        if not os.path.exists(main_branch_dir):
            self.log_message(f"Main Branch directory does not exist: {main_branch_dir}", "Test")
            return

        try:
            self.log_message(f"Stopping Test Branch server: {test_branch_name}...", "Test")
            port = self.get_port_by_test_branch_name(test_branch_name)
            if port and self.is_waitress_running(test_branch_name):
                self._terminate_process_by_port_or_dir(test_branch_name, port, test_branch_dir)
                self.log_message(f"Stopped Test Branch server: {test_branch_name}.", "Test")
            self.log_message(f"Stopping Main Branch server: {main_branch_name}...", "Test")
            port = self.gui.main_branch_manager.get_port_by_server_name(main_branch_name)
            if port and self.gui.main_branch_manager.is_waitress_running(main_branch_name):
                self._terminate_process_by_port_or_dir(main_branch_name, port, main_branch_dir)
                self.log_message(f"Stopped Main Branch server: {main_branch_name}.", "Test")
            timestamp = time.strftime("%m-%d-%Y %H.%M.%S")
            backup_dir = os.path.join(self.backups_dir, main_branch_name)
            os.makedirs(backup_dir, exist_ok=True)
            backup_path = os.path.join(backup_dir, f"{main_branch_name}_backup_{timestamp}.zip")
            shutil.make_archive(backup_path.replace(".zip", ""), "zip", main_branch_dir)
            self.log_message(f"Backup created for Main Branch '{main_branch_name}' at {backup_path}.", "Test")
            self.log_message(f"Deploying Test Branch '{test_branch_name}' to Main Branch '{main_branch_name}'...", "Test")
            shutil.rmtree(main_branch_dir)  # Remove existing Main Branch files
            shutil.copytree(test_branch_dir, main_branch_dir)  # Copy Test Branch files
            self.log_message(f"Test Branch '{test_branch_name}' deployed to Main Branch '{main_branch_name}'.", "Test")
            self.log_message(f"Restarting Main Branch server: {main_branch_name}...", "Test")
            port = self.gui.main_branch_manager.get_port_by_server_name(main_branch_name)
            if port:
                self.gui.main_branch_manager.start_server(main_branch_name, port, main_branch_dir)
                self.log_message(f"Main Branch server '{main_branch_name}' restarted successfully.", "Test")

        except Exception as e:
            self.log_message(f"Failed to deploy Test Branch '{test_branch_name}' to Main Branch '{main_branch_name}'. Error: {e}", "Test")
        self.update_button_states()

    def _terminate_process_by_port_or_dir(self, branch_name, port, branch_dir):
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr.port == port and conn.status == psutil.CONN_LISTEN:
                    if conn.pid:
                        proc = psutil.Process(conn.pid)
                        proc.terminate()
                        proc.wait(timeout=5)
                        self.log_message(f"Terminated process for '{branch_name}' on port {port}.", "Test")
                        break

            for proc in psutil.process_iter(['pid', 'name', 'cwd']):
                if proc.info['cwd'] and branch_name in proc.info['cwd']:
                    proc.terminate()
                    proc.wait(timeout=5)
                    self.log_message(f"Forcefully terminated process for '{branch_name}' using directory match.", "Test")
            time.sleep(3)

        except Exception as e:
            self.log_message(f"Failed to terminate process for '{branch_name}'. Error: {e}", "Test")

    #-----------------------
    # 2.8 DELETE TEST BRANCH
    #-----------------------
    def delete_test_branch(self, test_branch_name):
        server_dir = os.path.join(get_root_dir(), test_branch_name)
        trash_backup_dir = os.path.join(self.backups_dir, 'Trash')

        try:
            if os.path.exists(server_dir):
                os.makedirs(trash_backup_dir, exist_ok=True)
                timestamp = time.strftime("%m-%d-%Y_%H-%M-%S")
                backup_filename = f"{test_branch_name}_backup_{timestamp}.zip"
                backup_path = os.path.join(trash_backup_dir, backup_filename)
                shutil.make_archive(backup_path.replace(".zip", ""), 'zip', server_dir)
                self.log_message(f"Backup created for {test_branch_name} at {backup_path}.", "Test")
                shutil.rmtree(server_dir)
                release_port_for_server(test_branch_name)
                self.log_message(f"Deleted {test_branch_name}.", "Test")
                self.test_branches = [tb for tb in self.test_branches if tb[0] != test_branch_name]
                self.update_button_states()
            else:
                self.log_message(f"Test Branch directory does not exist: {server_dir}", "Test")
        except Exception as e:
            self.log_message(f"Failed to delete {test_branch_name}: {e}", "Test")

    #-----------------------
    # 2.9 CREATE GUI COMPONENTS
    #-----------------------
    def create_gui(self, parent):
        if not self.test_branches_frame or not self.test_branches_frame.winfo_exists():
            self.test_branches_frame = ttk.LabelFrame(parent, text="Test Branch Servers")
            self.test_branches_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self._populate_gui_widgets(self.test_branches_frame)
        self.log_message("TestBranchManager GUI created.", "Init")

    #-----------------------
    # 2.10 POPULATE GUI WIDGETS
    #-----------------------
    def _populate_gui_widgets(self, frame):
        retained_logs = {}
        for widget in frame.winfo_children():
            if isinstance(widget, scrolledtext.ScrolledText):
                test_branch_name = getattr(widget, "test_branch_name", None)
                if test_branch_name:
                    retained_logs[test_branch_name] = widget.get("1.0", tk.END)

        for widget in frame.winfo_children():
            widget.destroy()

        self.detect_test_branches()

        for test_branch_name, port, ssl in self.test_branches:
            self.create_test_branch_buttons(frame, test_branch_name, port, ssl)
            if test_branch_name in retained_logs:
                log_widget = getattr(self, f"{test_branch_name}_log_area", None)
                if log_widget:
                    log_widget.delete("1.0", tk.END)
                    log_widget.insert(tk.END, retained_logs[test_branch_name])

    #-----------------------
    # 2.11 CREATE TEST BRANCH BUTTONS
    #-----------------------
    def create_test_branch_buttons(self, parent, test_branch_name, port, ssl):
        from PIL import Image, ImageTk

        def load_icon(filename, size=(16, 16)):
            path = resource_path(f"assets/{filename}")
            img = Image.open(path).resize(size, Image.LANCZOS)
            return ImageTk.PhotoImage(img)

        outer = ttk.Frame(parent)
        outer.pack(fill=tk.X, pady=5)

        header = ttk.Frame(outer)
        header.pack(fill=tk.X, pady=(0, 4))

        dot = Canvas(header, width=20, height=20, highlightthickness=0)
        dot.pack(side=tk.LEFT, padx=(0, 4))
        color = "blue" if self.is_waitress_running(test_branch_name) else "orange"
        oval_id = dot.create_oval(2, 2, 18, 18, fill=color, outline="")

        lbls = ttk.Frame(header)
        lbls.pack(side=tk.LEFT)
        ttk.Label(lbls, text=test_branch_name, font=("Segoe UI", 11, "bold")).pack(anchor="w")
        row = ttk.Frame(lbls)
        row.pack(anchor="w")
        ttk.Label(row, text=f"Port: {port}", font=("Segoe UI", 9)).pack(side=tk.LEFT)
        ttk.Label(row, text=f"   [{'SSL' if ssl else 'No SSL'}]", font=("Segoe UI", 9)).pack(side=tk.LEFT)

        btn_row = ttk.Frame(outer)
        btn_row.pack(fill=tk.X, pady=(0, 4))

        icons = {
            "start":   load_icon("Play Icon.png"),
            "stop":    load_icon("Stop Icon.png"),
            "restart": load_icon("Restart Icon.png"),
            "files":   load_icon("View Files Icon.png"),
            "site":    load_icon("View Site Icon.png"),
            "send":    load_icon("Package & Send Updates Icon.png"),
            "apply":   load_icon("Download Updates Icon.png"),
            "test":    load_icon("Create New Test Branch Icon.png"),
        }

        def mk(btn_key, cmd, tip):
            btn = ttk.Button(btn_row, image=icons[btn_key], command=cmd, width=3)
            btn.image = icons[btn_key]
            ToolTip(btn, tip)
            return btn

        btn_start   = mk("start",   lambda: self.start_test_branch(test_branch_name, port),   "Start Server")
        btn_stop    = mk("stop",    lambda: self.stop_test_branch(test_branch_name),          "Stop Server")
        btn_restart = mk("restart", lambda: self.restart_test_branch(test_branch_name),       "Restart Server")

        for w in (btn_start, btn_stop, btn_restart):
            w.pack(side=tk.LEFT, padx=2)

        ttk.Label(btn_row, text="|").pack(side=tk.LEFT, padx=4)

        btn_files = mk("files", lambda: self.view_files(test_branch_name), "View Server Files")
        btn_site  = mk("site",  lambda: self.view_site(test_branch_name),  "Open in Browser")
        btn_files.pack(side=tk.LEFT, padx=(0,2))
        btn_site.pack(side=tk.LEFT,  padx=(2,0))

        ttk.Label(btn_row, text="|").pack(side=tk.LEFT, padx=4)

        btn_send  = mk("send",  lambda: self.package_and_send(test_branch_name),           "Package & Send")
        btn_apply = mk("apply", lambda: self.download_files_from_server(test_branch_name), "Apply Updates")
        btn_send.pack(side=tk.LEFT,  padx=(0,2))
        btn_apply.pack(side=tk.LEFT, padx=(2,0))

        ttk.Label(btn_row, text="|").pack(side=tk.LEFT, padx=4)

        btn_test = mk("test", lambda: self.create_test_branch(test_branch_name), "Create Test Branch")
        btn_test.pack(side=tk.LEFT, padx=2)

        log_area = scrolledtext.ScrolledText(outer, state="normal", height=7, font=("Consolas", 9))
        log_area.pack(fill=tk.BOTH, expand=True, padx=6, pady=(0,6))
        log_area.config(state='disabled')
        setattr(self, f"{test_branch_name}_log_area", log_area)
        log_nb = ttk.Notebook(outer)
        log_nb.pack(fill=tk.BOTH, expand=True, pady=3)
        self._setup_log_tabs(test_branch_name, log_nb)

        self.branch_widgets[test_branch_name] = {
            "status_dot": dot,
            "oval_id":    oval_id,
            "btn_start":  btn_start,
            "btn_stop":   btn_stop
        }
        self.update_branch_button_states(test_branch_name, self.is_waitress_running(test_branch_name))

    #-----------------------
    # 2.12 VIEW TEST BRANCH WEBSITE
    #-----------------------
    def view_site(self, test_branch_name):
        port = self.get_port_by_test_branch_name(test_branch_name)
        if port:
            url = f"http://127.0.0.1:{port}"
            open_browser_window(url, test_branch_name)

    #-----------------------
    # 2.13 VIEW TEST BRANCH FILES
    #-----------------------
    def view_files(self, test_branch_name):
        base_dir = os.path.join(get_root_dir(), test_branch_name)
        if not os.path.isdir(base_dir):
            self.log_message(f"Test branch directory does not exist: {base_dir}", "Test")
            return

        if not os.path.exists(self.notepad_plus_plus_path):
            self.log_message("Notepad++ not found. Check config.", "Test")
            return

        files_to_open = gather_files_to_open(
            base_dir, 
            self.exclude_dirs, 
            self.exclude_patterns, 
            file_extensions=('.py', '.html', '.css', '.js', '.json')
        )
        if files_to_open:
            try:
                subprocess.Popen([self.notepad_plus_plus_path, "-multiInst", "-nosession"] + files_to_open)
                self.log_message(f"Opened {len(files_to_open)} files for {test_branch_name} in Notepad++.", "Test")
            except Exception as e:
                self.log_message(f"Failed to open files for {test_branch_name}: {e}", "Test")
        else:
            self.log_message(f"No files to open for {test_branch_name}.", "Test")

    #-----------------------
    # 2.14 LOG MESSAGES
    #-----------------------
    def log_message(self, message, category="Test", level="info"):
        timestamp = time.strftime("[%B %d, %Y | %H:%M:%S]")
        full_message = f"{timestamp} [{category}] {message}\n"
        if hasattr(self, "events_logger") and self.events_logger:
            if level == "error":
                self.events_logger.error(message)
            elif level == "warning":
                self.events_logger.warning(message)
            else:
                self.events_logger.info(message)
        if hasattr(self.gui, "log_message"):
            self.gui.log_message(full_message, category)

    #-----------------------
    # 2.15 UPDATE BUTTON STATES
    #-----------------------
    def update_button_states(self):
        for test_branch_name, port, _ in self.test_branches:
            running = self.is_waitress_running(test_branch_name)
            branch_state_key = f"{test_branch_name}_running"
            if self.state_tracker.update_state(branch_state_key, running):
                self.update_branch_button_states(test_branch_name, running)

    def update_branch_button_states(self, test_branch_name, running):
        widgets = self.branch_widgets.get(test_branch_name)
        if not widgets:
            return

        widgets["btn_start"].config(state=tk.DISABLED if running else tk.NORMAL)
        widgets["btn_stop"].config(state=tk.NORMAL if running else tk.DISABLED)
        color = "blue" if running else "orange"
        widgets["status_dot"].itemconfig(widgets["oval_id"], fill=color)

    #-----------------------
    # 2.16 ENQUEUE AND PROCESS OUTPUT
    #-----------------------
    def enqueue_output(self, stream, test_branch_name):
        for line in iter(stream.readline, ""):
            self.output_queues[test_branch_name].put(line)
        stream.close()

    def process_output(self, test_branch_name):
        while True:
            try:
                line = self.output_queues[test_branch_name].get_nowait()
                log_widget = getattr(self, f"{test_branch_name}_log_area", None)
                if log_widget:
                    log_widget.insert(tk.END, line)
                    log_widget.see(tk.END)
            except queue.Empty:
                time.sleep(0.1)
            except Exception as e:
                self.log_message(f"Error in process_output for {test_branch_name}: {e}", "Test", level="error")
                break

    #=======================
    # 3. HELPER METHODS
    #=======================
    def is_waitress_running(self, test_branch_name):
        if test_branch_name in self.test_branch_processes:
            process = self.test_branch_processes[test_branch_name]
            if process.poll() is None:
                return True

        port = self.get_port_by_test_branch_name(test_branch_name)
        if port:
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr.port == port and conn.status == psutil.CONN_LISTEN:
                    return True

        return False

    def get_port_by_test_branch_name(self, test_branch_name):
        for tb_name, port, _ in self.test_branches:
            if tb_name == test_branch_name:
                return port
        return None
