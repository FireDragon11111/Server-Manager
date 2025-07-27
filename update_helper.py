# File: update_helper.py
"""
This helper updates the main Server Manager EXE.
Usage:
    update_helper.py <current_exe> <new_exe_backup_path> <backups_folder>
"""

import sys
import os
import time
import subprocess
import shutil

# ← NEW: we need psutil to find & kill lingering EXE processes
import psutil

def main():
    if len(sys.argv) < 4:
        print("Usage: update_helper.py <current_exe> <new_exe_backup_path> <backups_folder>")
        sys.exit(1)

    current_exe    = sys.argv[1]
    new_exe        = sys.argv[2]
    backups_folder = sys.argv[3]

    print("Updater Helper started.")
    print(f"Current EXE location: {current_exe}")
    print(f"New EXE from backup: {new_exe}")
    print(f"Backups folder: {backups_folder}")

    # 1. Wait for the original process to terminate itself.
    print("Waiting 5 seconds for the current process to terminate...")
    time.sleep(5)

    # ← NEW STEP: kill any lingering Server Manager.exe processes
    exe_name = os.path.basename(current_exe)
    print(f"Looking for lingering processes named '{exe_name}' to kill…")
    for proc in psutil.process_iter(['pid','name']):
        try:
            if proc.info['name'] == exe_name:
                print(f"Terminating PID {proc.pid} ({proc.info['name']})")
                proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # 2. Rename the current executable to include a timestamp
    base, ext = os.path.splitext(current_exe)
    ts = time.strftime("%Y%m%d%H%M%S")
    old_exe = f"{base}_{ts}.old{ext}"
    try:
        if os.path.exists(current_exe):
            print(f"Renaming '{current_exe}' to '{old_exe}'...")
            os.rename(current_exe, old_exe)
        else:
            print(f"No current EXE found at '{current_exe}', skipping rename.")
    except Exception as e:
        print("Error renaming current executable:", e)
        sys.exit(1)

    # 3. Confirm the rename took effect
    for _ in range(10):
        if not os.path.exists(current_exe):
            break
        print("Waiting for rename confirmation…")
        time.sleep(2)
    if os.path.exists(current_exe):
        print("Error: Current executable still exists after renaming.")
        sys.exit(1)

    # 4. Copy the new executable into place
    try:
        print("Copying new executable from backup to the original location...")
        shutil.copy2(new_exe, current_exe)
    except Exception as e:
        print("Error copying new executable:", e)
        sys.exit(1)

    # 5. Launch the new executable
    try:
        print("Launching the new executable…")
        subprocess.Popen([current_exe], cwd=os.path.dirname(current_exe))
    except Exception as e:
        print("Error launching new executable:", e)

    # 6. Give it a moment to settle
    time.sleep(5)

    # 7. Move the old executable into backups
    try:
        if os.path.exists(old_exe):
            dest = os.path.join(backups_folder, os.path.basename(old_exe))
            print(f"Moving old executable '{old_exe}' to backups folder '{dest}'…")
            shutil.move(old_exe, dest)
        else:
            print(f"No renamed EXE found at '{old_exe}', skipping backup move.")
    except Exception as e:
        print("Error moving old executable to backups:", e)

    print("Updater Helper completed.")

    # 8. Self-delete the helper
    try:
        del_cmd = f'cmd /c "timeout /t 3 /nobreak && del /f /q \"{sys.executable}\""'
        print("Scheduling self-deletion of updater helper…")
        subprocess.Popen(del_cmd, shell=True)
    except Exception as e:
        print("Error scheduling self-deletion:", e)

if __name__ == "__main__":
    main()
