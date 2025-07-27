import os
import sys
import time
import psutil  # pip install psutil
import subprocess
from datetime import datetime
from pathlib import Path

WATCHED_EXE = "Server Manager.exe"
CHECK_INTERVAL = 60   # Check every 1 minute
MAX_MISSES = 2        # 2 consecutive misses = 2 minutes max downtime

def log(msg, err=None):
    """
    Write a log entry to logs/Watchdog/watchdog_debug.log
    beside this EXE. Creates the folder if needed.
    """
    try:
        # base_dir = folder where this script (or EXE) lives
        base_dir = Path(sys.argv[0]).resolve().parent
        # logs/Watchdog under that
        log_folder = base_dir / "logs" / "Watchdog"
        log_folder.mkdir(parents=True, exist_ok=True)

        log_file = log_folder / "watchdog_debug.log"
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"[{now}] {msg}\n")
            if err is not None:
                f.write(f"    Error: {err}\n")
    except Exception as exc:
        # fallback to stderr if logging itself fails
        print(f"[LOGGING ERROR]: {exc} while logging '{msg}'", file=sys.stderr)

def kill_other_watchdogs():
    """
    Kills any running watchdog.exe processes (except the current one).
    Logs every process seen, kills only those that match watchdog names and aren't self.
    """
    my_pid = os.getpid()
    watchdog_names = ["watchdog.exe", "watchdog_checker.exe"]
    killed = []
    skipped = []
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            pid = proc.info.get('pid')
            name = (proc.info.get('name') or '').lower()
            exe = os.path.basename(proc.info.get('exe') or '').lower() if proc.info.get('exe') else ''
            log(f"Scanning process PID={pid}, name='{name}', exe='{exe}'")
            if pid == my_pid:
                skipped.append((pid, name, exe, "self"))
                continue
            if name in watchdog_names or exe in watchdog_names:
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                    log(f"Killed watchdog process: PID={pid}, name='{name}', exe='{exe}'")
                    killed.append((pid, name, exe))
                except Exception as e:
                    log(f"Failed to kill watchdog process: PID={pid}, name='{name}', exe='{exe}'", err=e)
            else:
                skipped.append((pid, name, exe, "not-matching"))
        except Exception as e:
            log(f"Exception while iterating processes.", err=e)
    log(f"kill_other_watchdogs(): killed={killed}, skipped={skipped}")

def is_server_manager_running():
    exe_name = WATCHED_EXE.lower()
    found = False
    matches = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            if proc.info['pid'] == os.getpid():
                continue
            name = (proc.info.get('name') or '').lower()
            exe = os.path.basename(proc.info.get('exe') or '').lower() if proc.info.get('exe') else ''
            cmdline = [str(a).lower() for a in (proc.info.get('cmdline') or [])]
            if (exe_name in name and "watchdog" not in name) or \
               (exe_name in exe and "watchdog" not in exe) or \
               (exe_name in " ".join(cmdline)):
                # Ignore Update Node processes
                if any('--update-node' in arg for arg in cmdline):
                    continue
                matches.append((proc.info['pid'], name, exe, " ".join(cmdline)))
                found = True
        except (psutil.NoSuchProcess, psutil.AccessDenied, KeyError) as e:
            log("Exception while iterating processes.", err=e)
            continue
    if found:
        log(f"Server Manager is running (check passed). Found: {matches}")
    else:
        log("Server Manager is NOT running (check failed).")
    return found

def main():
    log("Watchdog is starting up.")
    kill_other_watchdogs()
    log("Any other watchdogs killed. Continuing startup.")

    miss_count = 0
    log(f"Watchdog main loop entered. Will check every {CHECK_INTERVAL} seconds, max misses: {MAX_MISSES}.")
    while True:
        try:
            if is_server_manager_running():
                if miss_count != 0:
                    log("Server Manager detected as running again, resetting miss_count.")
                miss_count = 0
            else:
                miss_count += 1
                log(f"Missed detection #{miss_count} - Server Manager not running.")
                if miss_count >= MAX_MISSES:
                    try:
                        subprocess.Popen([WATCHED_EXE], creationflags=subprocess.DETACHED_PROCESS)
                        log("Server Manager restarted by watchdog.")
                    except Exception as e:
                        log("Failed to restart Server Manager.", err=e)
                    miss_count = 0
            time.sleep(CHECK_INTERVAL)
        except Exception as main_loop_error:
            log("Exception in main watchdog loop.", err=main_loop_error)
            time.sleep(10)

if __name__ == "__main__":
    main()
