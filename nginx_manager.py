"""
File: server_manager/nginx_manager.py
-------------------------------------
Manages all NGINX-related operations, including configuration generation, starting, stopping, and restarting NGINX.

TABLE OF CONTENTS
-----------------
1. IMPORTS
2. NginxManager Class Definition
   2.1 Initialization
   2.2 Ensure Directories
   2.3 Generate Configuration
   2.4 Validate Configuration
   2.5 Start NGINX
   2.6 Stop NGINX
   2.7 Restart NGINX
   2.8 Reload Configuration
   2.9 Create GUI Components
   2.10 Log Messages
   2.11 Update Button States
   2.12 Open NGINX Config
   2.13 Capture Output
   2.14 Check if NGINX is Running
"""

#=======================
# 1. IMPORTS
#=======================
import os
import subprocess
import time
import threading
from tkinter import ttk, scrolledtext, Canvas, messagebox
import tkinter as tk
from utils import is_process_running, get_root_dir, allocate_port_for_server, load_server_config, CONFIG_PATH, StateTracker, CERTBOT_LIVE_DIR, get_logger, ensure_log_folder, get_log_base_dir, set_config_value, get_config_value
import psutil
from pathlib import Path
from textwrap import wrap
import shutil
import socket
import re
import socket
import sys
import ssl
from datetime import datetime, timezone

def ensure_nginx_files_ready(nginx_dir: str | Path) -> None:
    nginx_dir = Path(nginx_dir)
    required_items: list[tuple[Path, bool]] = [
        (nginx_dir / "nginx.exe", False),
        (nginx_dir / "conf", True),
        (nginx_dir / "logs", True),
        (nginx_dir / "conf" / "mime.types", False),
        (nginx_dir / "conf" / "nginx.conf", False),
    ]
    for path, is_dir in required_items:
        if is_dir:
            if not path.is_dir():
                raise RuntimeError(f"NGINX required directory missing: {path}")
        else:
            if not path.is_file():
                raise RuntimeError(f"NGINX required file missing: {path}")

#=======================
# 2. NGINXMANAGER CLASS DEFINITION
#=======================
class NginxManager:
    #=======================
    # 2.1 INITIALIZATION
    #=======================
    def __init__(self, gui):
        self.gui     = gui
        self.servers = []
        self.events_logger = get_logger("Self", "NGINX_Events")
        if getattr(sys, "frozen", False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.abspath(__file__))
        if os.path.basename(base_dir).lower() != "server manager":
            candidate = os.path.join(base_dir, "Server Manager")
            if os.path.isdir(candidate):
                base_dir = candidate
        self.root_dir = base_dir
        self.nginx_executable = get_config_value(
            CONFIG_PATH,
            "nginx_executable",
            os.path.join(self.root_dir, "nginx", "nginx.exe")
        )
        self.conf_path = get_config_value(
            CONFIG_PATH,
            "nginx_conf",
            os.path.join(self.root_dir, "nginx", "conf", "nginx.conf")
        )
        norm = os.path.normpath(self.conf_path).lower()
        if not norm.endswith(os.path.join("nginx", "conf", "nginx.conf")):
            fixed = os.path.join(self.root_dir, "nginx", "conf", "nginx.conf")
            self.log(f"[warn] conf_path looked wrong → {self.conf_path}; fixing → {fixed}")
            self.conf_path = fixed
            set_config_value(CONFIG_PATH, "nginx_conf", "nginx/conf/nginx.conf")
        if not os.path.isabs(self.nginx_executable):
            self.nginx_executable = os.path.abspath(
                os.path.join(self.root_dir, self.nginx_executable)
            )
        if not os.path.isabs(self.conf_path):
            self.conf_path = os.path.abspath(
                os.path.join(self.root_dir, self.conf_path)
            )
        self.notepad_plus_plus_path = get_config_value(
            CONFIG_PATH,
            "notepad_path",
            r"D:\Notepad++\notepad++.exe"
        )
        self.certbot_path = get_config_value(
            CONFIG_PATH,
            "certbot_live_dir",
            r"C:\Certbot\live"
        )
        self.admin_email = get_config_value(
            CONFIG_PATH, "admin_email", "FireDragon111111@gmail.com"
        )
        self.status_dot  = None
        self.btn_start   = None
        self.btn_stop    = None
        self.btn_restart = None
        self.log_area    = None

        self.ensure_directories()
        self.state_tracker = StateTracker()
        self.log("NginxManager initialized and ready.")

    #-----------------------
    # 2.2 ENSURE DIRECTORIES
    #-----------------------
    def ensure_directories(self):
        import shutil, threading, traceback
        self.log(f"[ensure_directories] ENTRY — root_dir={self.root_dir} (thread={threading.current_thread().name})", level="warning")
        try:
            logs_dir = os.path.join(self.root_dir, "nginx", "logs")
            conf_dir = os.path.join(self.root_dir, "nginx", "conf")
            self.log(f"[ensure_directories] mkdir {logs_dir}", level="warning")
            os.makedirs(logs_dir, exist_ok=True)
            self.log(f"[ensure_directories] mkdir {conf_dir}", level="warning")
            os.makedirs(conf_dir, exist_ok=True)
        except Exception as e:
            self.log(f"[ensure_directories] FAILED to create dirs: {e}", level="error")
            self.log(traceback.format_exc(), level="error")
            return
        parent_root = os.path.abspath(os.path.join(self.root_dir, os.pardir))
        orphan_nginx = os.path.join(parent_root, "nginx")
        self.log(f"[ensure_directories] Computed orphan_nginx: {orphan_nginx}", level="warning")
        try:
            if os.path.isdir(orphan_nginx):
                try:
                    files = os.listdir(orphan_nginx)
                    self.log(f"[ensure_directories] Orphan contents: {files}", level="warning")
                except Exception as e:
                    self.log(f"[ensure_directories] Could not list orphan: {e}", level="warning")

                shutil.rmtree(orphan_nginx)
                self.log("[ensure_directories] Removed stray nginx folder!", level="warning")

            else:
                self.log("[ensure_directories] No stray nginx folder found.", level="warning")

        except Exception as e:
            self.log(f"[ensure_directories] Cleanup check failed: {e}", level="error")
            self.log(traceback.format_exc(), level="error")

    def ensure_all_certificates(self):
        try:
            self.log("Ensuring all certificates for SSL-enabled servers...")
            servers = (
                list(getattr(self.gui.main_branch_manager, "servers", []))
                + list(getattr(self.gui.test_branch_manager, "test_branches", []))
            )
            for name, _, ssl_enabled in servers:
                if ssl_enabled:
                    self.log(f"Ensuring certificate for domain: {name}")
                    success = self.ensure_certificate(name)
                    if success:
                        self.log(f"Certificate valid/obtained for: {name}")
                    else:
                        self.log(f"Failed to obtain certificate for: {name}", level="error")
            self.log("All certificates ensured.")
        except Exception as e:
            self.log(f"Error ensuring all certificates: {e}", level="error")

    #-----------------------
    # 2.3 GENERATE CONFIGURATION
    #-----------------------
    def generate_conf(self):
        def _nginx_running():
            return any(
                proc.info.get("name", "").lower() == "nginx.exe"
                for proc in psutil.process_iter(["name"])
            )
        while _nginx_running():
            try:
                subprocess.run(
                    [self.nginx_executable, "-s", "quit"],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except Exception:
                pass
            try:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/IM", "nginx.exe"],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except Exception:
                pass
            time.sleep(0.5)

        ensure_nginx_files_ready(os.path.join(self.root_dir, "nginx"))
        main_servers = self.gui.main_branch_manager.servers
        test_branches = self.gui.test_branch_manager.test_branches

        servers = main_servers + test_branches

        self.log(f"Combined servers list: {servers}")

        internal_ip = self._get_internal_ip()
        self.log(f"Detected internal IP: {internal_ip}")

        internal_subnet = self._get_internal_subnet() or "192.168.0"

        self.update_hosts_file(servers, internal_ip)

        conf_lines = [
            'worker_processes auto;',
            '',
            'events {',
            '    worker_connections 2048;',
            '}',
            '',
            'http {',
            '    include       mime.types;',
            '    default_type  application/octet-stream;',
            f'    error_log  "{os.path.join(self.root_dir, "nginx", "logs", "error.log").replace("\\", "/")}";',
            f'    access_log "{os.path.join(self.root_dir, "nginx", "logs", "access.log").replace("\\", "/")}";',
            '    sendfile        on;',
            '    tcp_nopush      on;',
            '    tcp_nodelay     on;',
            '    keepalive_timeout 60s;',
            '    keepalive_requests 1000;',
            '    gzip on;',
            '    gzip_static on;',
            '    gzip_min_length 256;',
            '    gzip_comp_level 5;',
            '    gzip_types application/javascript application/json text/css text/javascript text/plain application/xml text/xml font/woff2;',
            '    gzip_vary on;',
            '    client_max_body_size 5G;',
            '    client_header_buffer_size 1k;',
            '    large_client_header_buffers 4 8k;',
            '    proxy_buffers 32 16k;',
            '    proxy_buffer_size 128k;',
            '    proxy_busy_buffers_size 256k;',
            '    proxy_connect_timeout 30s;',
            '    proxy_send_timeout 90s;',
            '    proxy_read_timeout 90s;',
            '    server_names_hash_bucket_size 64;',
            f'    proxy_cache_path "{os.path.join(self.root_dir, "nginx", "cache").replace("\\", "/")}" levels=1:2 keys_zone=my_cache:10m max_size=10g inactive=60m use_temp_path=off;',
            '    add_header X-Frame-Options SAMEORIGIN always;',
            '    add_header X-Content-Type-Options nosniff;',
            '    add_header X-XSS-Protection "1; mode=block";',
            '    server_tokens off;',
            '',
            '    map $remote_addr $is_local_or_internal {',
            '        default 0;',
            '        127.0.0.1 1;',
            '        ::1 1;',
            f'        ~^{internal_subnet}\\..* 1;',
            '    }',
            '',
        ]

        for server in servers:
            if len(server) == 3:
                server_name, port, ssl_enabled = server
                if ssl_enabled:
                    conf_lines.extend([
                        '    server {',
                        '        listen 80;',
                        f'        server_name {server_name} www.{server_name};',
                        '        return 301 https://$host$request_uri;',
                        '    }',
                        '',
                    ])

        for server in servers:
            if len(server) == 3:
                server_name, port, _ = server
                self._add_server_block(conf_lines, server_name, port, internal_ip)

        if self.is_update_node_running():
            self.add_update_node_block(conf_lines)
        else:
            self.log("Update Node server not detected on port 5001. Skipping Update Node block.")

        conf_lines.append('}')

        try:
            with open(self.conf_path, 'w') as f:
                f.write('\n'.join(conf_lines))
            self.log("NGINX configuration generated successfully.")
        except Exception as e:
            self.log(f"Failed to write NGINX configuration: {e}")

    def _is_cert_valid(self, cert_path):
        try:
            cert = ssl._ssl._test_decode_cert(cert_path)
            expires = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
            expires = expires.replace(tzinfo=timezone.utc)
            return expires > datetime.now(timezone.utc)
        except Exception as e:
            self.log(f"Error validating certificate {cert_path}: {e}")
            return False

    #-----------------------
    # Helper Method: Ensure Certificate
    #-----------------------
    def ensure_certificate(self, domain):
        cert_dir = os.path.join(self.certbot_path, domain)
        cert_path = os.path.join(cert_dir, "fullchain.pem")
        key_path = os.path.join(cert_dir, "privkey.pem")
        if os.path.exists(cert_path) and os.path.exists(key_path) and self._is_cert_valid(cert_path):
            self.log(f"Valid certificate for {domain} already exists; skipping issuance.")
            return True
        was_running = self.is_nginx_running()
        if was_running:
            self.log(f"Stopping NGINX to obtain certificate for {domain}…")
            self.stop_nginx()
            time.sleep(1)
        self.log(f"Obtaining certificate for {domain} via HTTP‑01 (force renewal)…")
        cmd = [
            "certbot",
            "certonly",
            "--standalone",
            "--preferred-challenges", "http",
            "--force-renewal",
            "-d", domain,
            "--non-interactive", "--agree-tos",
            "-m", self.admin_email,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0 or not (os.path.exists(cert_path) and os.path.exists(key_path)):
            err = (result.stderr or result.stdout or "<no output>").strip()
            self.log(f"Certbot failed for {domain}: {err}", level="error")
            if was_running:
                self.log(f"Restarting NGINX after failed cert attempt for {domain}…")
                self.gui.after(0, self.start_nginx)
                time.sleep(1)
            return False
        self.log(f"Certificate for {domain} obtained/renewed successfully.")
        if was_running:
            self.log(f"Restarting NGINX after certificate generation for {domain}…")
            self.gui.after(0, self.start_nginx)
            time.sleep(1)
        return True

    #-----------------------
    # Helper Method: Add Update Node Block
    #-----------------------
    def add_update_node_block(self, conf_lines):
        import os

        domain = "update-node.firecrafting.net"
        has_cert = self.ensure_certificate(domain)
        update_node_ip = self._get_internal_ip()

        error_log_path = os.path.join(
            self.root_dir, "nginx", "logs", "update-node-error.log"
        ).replace("\\", "/")
        access_log_path = os.path.join(
            self.root_dir, "nginx", "logs", "update-node-access.log"
        ).replace("\\", "/")

        if has_cert:
            block = [
                '    server {',
                '        listen 443 ssl;',
                f'        server_name {domain};',
                f'        ssl_certificate "C:/Certbot/live/{domain}/fullchain.pem";',
                f'        ssl_certificate_key "C:/Certbot/live/{domain}/privkey.pem";',
                '',
                '        # Proxy all requests to the Update Node server',
                '        location / {',
                f'            proxy_pass http://{update_node_ip}:5001/;',
                '            proxy_set_header Host $host;',
                '            proxy_set_header X-Real-IP $remote_addr;',
                '            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;',
                '            proxy_set_header X-Forwarded-Proto $scheme;',
                '            client_max_body_size 5G;',
                '        }',
                '',
                '        # Security headers',
                '        add_header X-Frame-Options SAMEORIGIN always;',
                '        add_header X-Content-Type-Options nosniff;',
                '        add_header X-XSS-Protection "1; mode=block";',
                '',
                f'        error_log "{error_log_path}";',
                f'        access_log "{access_log_path}";',
                '    }',
            ]
        else:
            block = [
                '    server {',
                '        listen 80;',
                f'        server_name {domain};',
                '',
                '        # Proxy all requests to the Update Node server',
                '        location / {',
                f'            proxy_pass http://{update_node_ip}:5001/;',
                '            proxy_set_header Host $host;',
                '            proxy_set_header X-Real-IP $remote_addr;',
                '            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;',
                '            proxy_set_header X-Forwarded-Proto $scheme;',
                '            client_max_body_size 5G;',
                '        }',
                '',
                '        # Security headers',
                '        add_header X-Frame-Options SAMEORIGIN always;',
                '        add_header X-Content-Type-Options nosniff;',
                '        add_header X-XSS-Protection "1; mode=block";',
                '',
                f'        error_log "{error_log_path}";',
                f'        access_log "{access_log_path}";',
                '    }',
            ]
        conf_lines.extend(block)

    #-----------------------
    # Helper Method: Check if Update Node is Running on Port 5001
    #-----------------------
    def is_update_node_running(self):
        try:
            with socket.create_connection(("127.0.0.1", 5001), timeout=1):
                return True
        except OSError as ex:
            if getattr(ex, 'errno', None) not in (111, 10061):
                self.log(f"Error checking Update Node on port 5001: {ex}", level="warning")
            return False

    #-----------------------
    # 2.10 UPDATE HOSTS FILE
    #-----------------------
    def update_hosts_file(self, servers, internal_ip):
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        backup_path = hosts_path + ".backup"

        try:
            if not os.access(hosts_path, os.W_OK):
                self.events_logger.error("Insufficient permissions to update the hosts file. Please run the program as an administrator.")
                return

            if not os.path.exists(backup_path):
                shutil.copyfile(hosts_path, backup_path)

            with open(hosts_path, "r") as f:
                lines = f.readlines()
            managed_domains = set([server[0] for server in servers] + ["update-node.firecrafting.net"])
            filtered_lines = []
            for line in lines:
                parts = line.strip().split()
                if len(parts) >= 2:
                    hostname = parts[1]
                    if hostname in managed_domains:
                        continue
                filtered_lines.append(line)

            new_lines = []
            in_block = False
            for line in filtered_lines:
                if line.strip() == "## SERVER MANAGER START":
                    in_block = True
                    continue
                if line.strip() == "## SERVER MANAGER END":
                    in_block = False
                    continue
                if not in_block:
                    new_lines.append(line)

            new_lines.append("## SERVER MANAGER START\n")
            for domain in managed_domains:
                if domain == "update-node.firecrafting.net":
                    if self.is_update_node_running():
                        new_lines.append("192.168.1.247   update-node.firecrafting.net\n")
                    else:
                        self.log("Update Node server not detected; skipping hosts entry for update-node.firecrafting.net.")
                else:
                    new_lines.append(f"{internal_ip} {domain}\n")
            new_lines.append("## SERVER MANAGER END\n")

            with open(hosts_path, "w") as f:
                f.writelines(new_lines)

        except PermissionError:
            self.events_logger.error("Permission denied. Please run the program as an administrator.")
        except Exception as e:
            self.events_logger.error(f"Failed to update hosts file: {e}")

    #-----------------------
    # 2.11 _ADD SERVER BLOCK
    #-----------------------
    def _add_server_block(self, conf_lines, server_name, port, internal_ip):
        ssl_cert = os.path.join(self.certbot_path, server_name, "fullchain.pem").replace("\\", "/")
        ssl_key = os.path.join(self.certbot_path, server_name, "privkey.pem").replace("\\", "/")

        if server_name == "palaciosenterpises.space":
            website_static_path = os.path.join(self.root_dir, "..", server_name, "static").replace("\\", "/")
            static_files_block = [
                '        location /static/ {',
                f'            alias "{website_static_path}/";',
                '            expires max;',
                '            add_header Cache-Control "public";',
                '        }',
            ]
        else:
            static_files_block = [
                f'        location /static/ {{',
                f'            proxy_pass http://127.0.0.1:{port}/static/;',
                '            proxy_cache my_cache;',
                '            proxy_cache_valid 200 1h;',
                '            proxy_cache_valid 404 1m;',
                '            proxy_cache_use_stale error timeout invalid_header updating http_500 http_502 http_503 http_504;',
                '            expires max;',
                '            log_not_found off;',
                '            access_log off;',
                '            types {',
                '                text/html html;',
                '            }',
                '        }',
            ]

        cert_path = os.path.join(self.certbot_path, server_name, "fullchain.pem")
        has_cert = os.path.exists(cert_path) and self._is_cert_valid(cert_path)

        if has_cert:
            self.log(f"Adding HTTPS server block for {server_name} (port 443, proxy to {port})")
            main_server_block = [
                '    server {',
                '        listen 443 ssl;',
                f'        server_name {server_name};',
                f'        ssl_certificate "{ssl_cert}";',
                f'        ssl_certificate_key "{ssl_key}";',
                '        location / {',
                f'            proxy_pass http://127.0.0.1:{port};',
                '            proxy_cache my_cache;',
                '            proxy_cache_valid 200 1h;',
                '            proxy_cache_valid 404 1m;',
                '            proxy_cache_use_stale error timeout invalid_header updating http_500 http_502 http_503 http_504;',
                '        }',
            ] + static_files_block + [
                '    }',
                ''
            ]
        else:
            self.log(f"Adding HTTP server block for {server_name} (port 80, proxy to {port})")
            main_server_block = [
                '    server {',
                '        listen 80;',
                f'        server_name {server_name};',
                '        location / {',
                f'            proxy_pass http://127.0.0.1:{port};',
                '        }',
            ] + static_files_block + [
                '    }',
                ''
            ]

        conf_lines.extend(main_server_block)

    #-----------------------
    # 2.12 _GET INTERNAL IP
    #-----------------------
    def _get_internal_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            internal_ip = s.getsockname()[0]
        except Exception as e:
            self.events_logger.error(f"Failed to detect internal IP: {e}")
            internal_ip = "127.0.0.1"
        finally:
            s.close()
        return internal_ip

    #-----------------------
    # 2.13 _GET INTERNAL SUBNET
    #-----------------------
    def _get_internal_subnet(self):
        try:
            internal_ip = self._get_internal_ip()
            self.log(f"Detected internal IP: {internal_ip}")
            match = re.match(r"^(192\.168\.\d+|10\.\d+|172\.(1[6-9]|2[0-9]|3[0-1]))\.", internal_ip)
            if match:
                subnet = match.group(1)
                self.log(f"Detected internal subnet: {subnet}")
                return subnet
            else:
                self.log("Unable to determine internal subnet. Defaulting to 192.168.0.")
                return "192.168.0"
        except Exception as e:
            self.log(f"Error detecting internal subnet: {e}")
            return "192.168.0"

    # ─────────────────────────────────────────────────────────
    # 2.4  VALIDATE CONFIGURATION
    # ─────────────────────────────────────────────────────────
    def validate_conf(self) -> bool:
        try:
            result = subprocess.run(
                [
                    self.nginx_executable,
                    "-p", os.path.join(self.root_dir, "nginx"),
                    "-t",
                    "-c", self.conf_path
                ],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                self.log(f"[NGINX Validation Error]\n{result.stderr.strip()}")
                return False
            self.log("[NGINX] Configuration is valid.")
            return True
        except Exception as e:
            self.log(f"[NGINX] Error during validation: {e}")
            return False

    #-----------------------
    # 2.5 START NGINX
    #-----------------------
    def start_nginx(self):
        self.generate_conf()
        try:
            ensure_nginx_files_ready(os.path.join(self.root_dir, "nginx"))
            error_log_path = os.path.join(self.root_dir, "nginx", "logs", "error.log")
            if os.path.isfile(error_log_path):
                open(error_log_path, 'w').close()
            if (not os.path.isfile(self.conf_path)) or os.path.getsize(self.conf_path) < 64:
                self.log("nginx.conf missing or too small – regenerating before start.")
                self.generate_conf()
                if os.path.getsize(self.conf_path) < 64:
                    self.log("nginx.conf still incomplete; aborting automatic start.")
                    return
            process = subprocess.Popen(
                [self.nginx_executable,
                 '-p', os.path.join(self.root_dir, "nginx"),
                 '-c', self.conf_path],
                cwd=os.path.join(self.root_dir, "nginx"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            threading.Thread(
                target=self.capture_output,
                args=(process.stdout, "STDOUT"),
                daemon=True
            ).start()
            threading.Thread(
                target=self.capture_output,
                args=(process.stderr, "STDERR"),
                daemon=True
            ).start()
            time.sleep(2)
            if self.is_nginx_running():
                self.log("NGINX started successfully.")
                set_config_value(CONFIG_PATH, "nginx_running", True)
            else:
                non_inert_errors = []
                if os.path.isfile(error_log_path):
                    with open(error_log_path, 'r', encoding='utf-8') as f:
                        for line in f:
                            if "OpenEvent(" in line or "CreateFile(" in line:
                                continue
                            non_inert_errors.append(line.strip())
                if non_inert_errors:
                    self.log("Failed to start NGINX. See logs for details.", level="error")
                    messagebox.showerror("Error", "Failed to start NGINX. Check the logs for details.")
                else:
                    self.log("NGINX start had only benign alerts; treating as successful.", level="warning")
                    set_config_value(CONFIG_PATH, "nginx_running", True)
            self.gui.after(250, self.update_button_states)

        except FileNotFoundError:
            self.log("NGINX executable not found. Check the path in the configuration.")
            messagebox.showerror("Error", "NGINX executable not found. Check the path in the configuration.")
        except Exception as e:
            self.log(f"Unexpected error starting NGINX: {e}", level="error")
            messagebox.showerror("Error", f"Unexpected error starting NGINX: {e}")


    def stop_nginx(self):
        try:
            for proc in psutil.process_iter(['name']):
                name = proc.info.get('name') or ''
                if 'nginx.exe' in name.lower():
                    proc.terminate()

            time.sleep(3)
            subprocess.run(
                ['taskkill', '/F', '/IM', 'nginx.exe', '/T'],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            self.log("NGINX stopped.")
            self.gui.after(250, self.update_button_states)
            set_config_value(CONFIG_PATH, "nginx_running", False)

        except Exception as e:
            self.log(f"Failed to stop NGINX: {e}")

    #-----------------------
    # 2.7 RESTART NGINX
    #-----------------------
    def restart_nginx(self):
        self.stop_nginx()
        time.sleep(2)
        self.start_nginx()
        self.gui.after(500, self.update_button_states)

    # ─────────────────────────────────────────────────────────
    # 2.8  RELOAD CONFIGURATION
    # ─────────────────────────────────────────────────────────
    def reload_conf(self):
        import os
        import subprocess
        from tkinter import messagebox

        def _nginx_running():
            return any(
                proc.info.get("name", "").lower() == "nginx.exe"
                for proc in psutil.process_iter(["name"])
            )

        # Ensure no existing Nginx processes remain before reload
        while _nginx_running():
            try:
                subprocess.run(
                    [self.nginx_executable, "-s", "quit"],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except Exception:
                pass
            try:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/IM", "nginx.exe"],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except Exception:
                pass
            time.sleep(0.5)

        try:
            # Recreate directories & remove stray folder
            self.ensure_directories()

            # If not running, start fresh
            if not self.is_nginx_running():
                self.log("NGINX is not running – starting it.")
                self.start_nginx()
                return

            # Validate config
            if not self.validate_conf():
                self.log("NGINX configuration is invalid – reload aborted.")
                return

            # Perform reload, silencing the OpenEvent alert
            cmd = [
                self.nginx_executable,
                "-p",
                os.path.join(self.root_dir, "nginx"),
                "-s",
                "reload",
            ]
            result = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )

            # Filter out only the benign OpenEvent alerts
            if result.stderr:
                remaining = [
                    line
                    for line in result.stderr.splitlines()
                    if "OpenEvent(" not in line
                ]
                if remaining:
                    # Log or show any other real errors
                    error_text = "\n".join(remaining)
                    self.log(f"NGINX reload messages:\n{error_text}", level="warning")

            # Check exit status
            if result.returncode != 0:
                self.log(f"NGINX reload failed (exit {result.returncode}).", level="error")
                messagebox.showerror("Error", f"Failed to reload NGINX (exit {result.returncode}).")
                return

            # Success
            self.log("NGINX configuration reloaded successfully.")
            self.gui.after(250, self.update_button_states)

        except Exception as e:
            self.log(f"Failed to reload NGINX: {e}", level="error")
            messagebox.showerror("Error", f"Failed to reload NGINX:\n{e}")

    #-----------------------
    # 2.9 CREATE GUI COMPONENTS
    #-----------------------
    def create_gui(self, parent):
        from utils import refresh_gui
        if hasattr(self, 'nginx_frame'):
            self.nginx_frame.destroy()

        self.nginx_frame = ttk.LabelFrame(parent, text="NGINX Management")
        self.nginx_frame.pack(fill=tk.X, pady=5)

        refreshed = refresh_gui(
            self.nginx_frame,
            [(self, )],
            lambda frame, manager: manager._populate_gui_widgets(frame),
            persistent_widgets=[self.log_area] if hasattr(self, 'log_area') else None
        )

        if not refreshed:
            self.events_logger.warning("[DEBUG - nginx_manager.py] Failed to refresh nginx_frame.")

    def _populate_gui_widgets(self, frame):
        try:
            for widget in frame.winfo_children():
                widget.destroy()

            control_frame = ttk.Frame(frame)
            control_frame.pack(fill=tk.X, pady=5)

            self.status_dot = Canvas(control_frame, width=20, height=20)
            self.status_dot.pack(side=tk.LEFT, padx=5)
            initial_color = "green" if self.is_nginx_running() else "red"
            self.status_dot.create_oval(2, 2, 18, 18, fill=initial_color, outline="")

            self.btn_start = ttk.Button(control_frame, text="Start NGINX", command=self.start_nginx)
            self.btn_start.pack(side=tk.LEFT, padx=5)

            self.btn_stop = ttk.Button(control_frame, text="Stop NGINX", command=self.stop_nginx)
            self.btn_stop.pack(side=tk.LEFT, padx=5)

            self.btn_restart = ttk.Button(control_frame, text="Restart NGINX", command=self.restart_nginx)
            self.btn_restart.pack(side=tk.LEFT, padx=5)

            ttk.Button(control_frame, text="Open NGINX Config", command=self.open_nginx_conf).pack(side=tk.LEFT, padx=5)
            ttk.Button(control_frame, text="Reload Config", command=self.reload_conf).pack(side=tk.LEFT, padx=5)

            if not hasattr(self, 'log_area') or not self.log_area or not self.log_area.winfo_exists():
                self.log_area = scrolledtext.ScrolledText(frame, height=8, width=100)
                self.log_area.pack(fill=tk.X, pady=5)

            self.update_button_states()

        except Exception as e:
            self.events_logger.error(f"[DEBUG - nginx_manager.py] Error while populating widgets: {e}")

    #-----------------------
    # 2.10 LOG MESSAGES
    #-----------------------
    def log(self, message, level="info"):
        if hasattr(self, "events_logger") and self.events_logger:
            if level == "error":
                self.events_logger.error(message)
            elif level == "warning":
                self.events_logger.warning(message)
            else:
                self.events_logger.info(message)
        
        if hasattr(self, "log_area") and self.log_area and self.log_area.winfo_exists():
            self.log_area.after(
                0,
                lambda msg=message: (
                    self.log_area.insert(tk.END, msg + "\n"),
                    self.log_area.see(tk.END)
                )
            )

    def attach_log_widget(self, widget):
        if isinstance(widget, ttk.Notebook):
            self._setup_log_tabs(widget)
        else:
            self.log_area = widget

    def _detect_log_paths(self) -> dict[str, Path]:
        base = Path(get_log_base_dir())
        all_files = list(base.rglob("*.log*"))
        groups: dict[str, Path] = {}
        for f in all_files:
            m = re.match(r"^(.*?)(?:\.\d{4}-\d{2}-\d{2})?\.log", f.name)
            if m:
                prefix = m.group(1)
            else:
                prefix = f.stem
            rel = f.relative_to(base).parent
            tab_label = str(rel / prefix)
            prev = groups.get(tab_label)
            if not prev or f.stat().st_mtime > prev.stat().st_mtime:
                groups[tab_label] = f
        return groups

    def _setup_log_tabs(self, notebook: ttk.Notebook):
        logs_root = Path(self.root_dir) / "logs" / "Nodes" / "NginxManager"
        all_files = list(logs_root.rglob("*.log*"))

        log_map = {
            str(p.relative_to(logs_root)): p
            for p in all_files
        }

        sorted_logs = sorted(
            log_map.items(),
            key=lambda kv: kv[1].stat().st_mtime,
            reverse=True
        )

        MAX_TABS = 10
        displayed = sorted_logs[:MAX_TABS]
        hidden_count = len(sorted_logs) - len(displayed)
        style = ttk.Style()
        style.configure("WrappedLog.TNotebook.Tab", wraplength=100)
        notebook.configure(style="WrappedLog.TNotebook")

        self._log_widgets = {}
        for name, path in displayed:
            frame = ttk.Frame(notebook)
            txt = scrolledtext.ScrolledText(
                frame,
                state="disabled",
                height=10,
                font=("Consolas", 9)
            )
            txt.pack(fill=tk.BOTH, expand=True)
            notebook.add(
                frame,
                text="\n".join(wrap(name, width=15))
            )
            self._log_widgets[name] = txt
            threading.Thread(
                target=self._tail_log_file,
                args=(txt, path),
                daemon=True
            ).start()

        if hidden_count > 0:
            more_frame = ttk.Frame(notebook)
            lbl = tk.Label(
                more_frame,
                text=f"{hidden_count} more logs hidden…",
                anchor="center"
            )
            lbl.pack(fill=tk.BOTH, expand=True, pady=20)
            notebook.add(
                more_frame,
                text=f"...(+{hidden_count})"
            )

    def _tail_log_file(self, widget: scrolledtext.ScrolledText, file_path: Path):
        with open(file_path, 'r', encoding='utf-8') as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.3)
                    continue
                text = line.rstrip()
                if "OpenEvent(" in text:
                    continue
                widget.after(0, self._append_log_line, widget, text)

    def _append_log_line(self, widget: scrolledtext.ScrolledText, line: str):
        widget.config(state='normal')
        widget.insert(tk.END, line + "\n")
        widget.see(tk.END)
        widget.config(state='disabled')

    #-----------------------
    # 2.11 UPDATE BUTTON STATES
    #-----------------------
    def update_button_states(self):
        is_running = self.is_nginx_running()

        if self.status_dot and self.status_dot.winfo_exists():
            self.status_dot.delete("all")
            color = "green" if is_running else "red"
            w = int(self.status_dot.cget("width"))
            h = int(self.status_dot.cget("height"))
            self.status_dot.create_oval(2, 2, w - 2, h - 2, fill=color, outline="")

        if self.btn_start and self.btn_start.winfo_exists():
            self.btn_start.config(state=tk.DISABLED if is_running else tk.NORMAL)
        if self.btn_stop and self.btn_stop.winfo_exists():
            self.btn_stop.config(state=tk.NORMAL if is_running else tk.DISABLED)
        if self.btn_restart and self.btn_restart.winfo_exists():
            self.btn_restart.config(state=tk.NORMAL)

        try:
            self.gui.draw_tab_buttons()
        except Exception:
            pass

    #-----------------------
    # 2.12 OPEN NGINX CONFIG
    #-----------------------
    def open_nginx_conf(self):
        try:
            if os.path.exists(self.conf_path):
                if os.path.exists(self.notepad_plus_plus_path):
                    subprocess.Popen([self.notepad_plus_plus_path, self.conf_path])
                    self.log("Opened nginx.conf in Notepad++.")
                else:
                    self.log("Notepad++ executable not found.")
                    messagebox.showerror("Error", "Notepad++ executable not found.")
            else:
                self.log(f"nginx.conf not found at {self.conf_path}.")
                messagebox.showerror("Error", f"nginx.conf not found at {self.conf_path}.")
        except Exception as e:
            self.log(f"Failed to open nginx.conf: {e}")
            messagebox.showerror("Error", f"Failed to open nginx.conf: {e}")

    #-----------------------
    # 2.13 CAPTURE OUTPUT
    #-----------------------
    def capture_output(self, pipe, pipe_name):
        try:
            with pipe:
                for raw in iter(pipe.readline, ''):
                    line = raw.rstrip()
                    # Suppress the Windows OpenEvent alert
                    if pipe_name == "STDERR" and "OpenEvent(" in line:
                        continue
                    self.log(f"[{pipe_name}] {line}")
            self.log(f"[{pipe_name}] output capture ended.")
        except Exception as e:
            self.log(f"[{pipe_name}] Error capturing output: {e}", level="error")

    #-----------------------
    # 2.14 CHECK IF NGINX IS RUNNING
    #-----------------------
    def is_nginx_running(self):
        return is_process_running("nginx.exe")
