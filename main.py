# main.py

# ──────────────────────────────────────────────────────────────────────────────
# PyInstaller one-file tempdir cleanup: must run before any bundled imports!
import sys, os, shutil, atexit

# Suppress all Windows error popups for EXE (critical error dialogs, crash popups, open file errors, etc.)
if os.name == 'nt':
    try:
        import ctypes
        SEM_FAILCRITICALERRORS = 0x0001
        SEM_NOGPFAULTERRORBOX    = 0x0002
        SEM_NOOPENFILEERRORBOX   = 0x8000
        # Set process error mode to suppress all popups
        ctypes.windll.kernel32.SetErrorMode(
            SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX
        )
    except Exception:
        pass

# ── Startup cleanup: remove any stale _MEI* temp dirs left over from previous runs
_current_mei = getattr(sys, "_MEIPASS", None)
# Determine the parent directory in which PyInstaller unpacked (_MEIPASS) or the system TEMP
_tmp_root = None
if _current_mei and os.path.isdir(_current_mei):
    _tmp_root = os.path.dirname(_current_mei)
else:
    # fallback to the OS temp dir
    _tmp_root = os.getenv("TMP") or os.getenv("TEMP")

if _tmp_root and os.path.isdir(_tmp_root):
    for _name in os.listdir(_tmp_root):
        if not _name.startswith("_MEI"):
            continue
        _path = os.path.join(_tmp_root, _name)
        # skip the one we're running from
        if _path == _current_mei:
            continue
        try:
            shutil.rmtree(_path, ignore_errors=True)
        except Exception:
            pass

def _cleanup_pyinstaller_tempdir():
    """
    Remove the PyInstaller one-file extraction folder on exit.
    """
    mei = getattr(sys, "_MEIPASS", None)
    if mei and os.path.isdir(mei):
        try:
            shutil.rmtree(mei, ignore_errors=True)
        except Exception:
            pass

# Register it immediately
atexit.register(_cleanup_pyinstaller_tempdir)
# ──────────────────────────────────────────────────────────────────────────────

#=======================
# 1. IMPORTS
#=======================
from multiprocessing import freeze_support
from utils import ensure_log_folder

#=======================
# 2. LAUNCH UPDATE-NODE
#=======================
def serve_update_node():
    """
    If called with --update-node, import and serve only the
    Flask app via Waitress on port 5001 (no GUI).
    """
    from update_node_server_host import app as flask_app
    from waitress import serve

    # You can tweak host/port here if you like
    serve(flask_app, host="0.0.0.0", port=5001)

#=======================
# 3. LAUNCH GUI
#=======================
def serve_gui():
    """
    Normal entrypoint: start the Tkinter GUI.
    """
    from gui import ServerManagerGUI
    gui = ServerManagerGUI()
    gui.mainloop()

#=======================
# 4. MAIN
#=======================
def main():
    # If the special flag is present, run only the update-node host
    if "--update-node" in sys.argv:
        serve_update_node()
    else:
        serve_gui()

#=======================
# 5. STARTUP + CRASH LOGGING
#=======================
if __name__ == "__main__":
    from datetime import datetime
    import traceback

    freeze_support()
    try:
        main()
    except Exception:
        # ensure we capture any startup crash
        crash_dir = ensure_log_folder("Self", "Crash")
        fn = crash_dir / f"crash_{datetime.now():%Y%m%d_%H%M%S}.log"
        with open(fn, "w", encoding="utf-8") as fp:
            traceback.print_exc(file=fp)
        # Re-raise so Windows still shows the standard error dialog
        raise
