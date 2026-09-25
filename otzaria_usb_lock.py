# -*- coding: utf-8 -*-
"""
Otzaria USB Lock (PySide6 edition)
-----------------------------------
Prepares a USB drive for safe distribution: formats it to NTFS and locks
write access so only the current Windows account can write to it. Every
other computer can read/run from it but not write to it, which blocks the
main way flash-drive malware spreads.

Why PySide6 instead of Tkinter: Qt's text engine implements the full
Unicode Bidirectional Algorithm natively, so Hebrew strings are given in
plain logical (typed) order and Qt displays them correctly automatically -
no manual character reordering, which is exactly the piece that kept
going wrong under Tkinter/HTA.

Every OS command below is called with an explicit argument list (never a
shell string), so there is nothing for cmd.exe to misquote.
"""

import os
import sys
import ctypes
import string
import tempfile
import subprocess
import time
import json
import shutil
import stat

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QIcon, QPixmap, QFont
from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QComboBox, QFrame,
    QVBoxLayout, QHBoxLayout, QPlainTextEdit, QDialog, QLineEdit, QSizePolicy
)


# --------------------------------------------------------------------------
# Resource path helper (works both as a plain .py and as a PyInstaller .exe)
# --------------------------------------------------------------------------
def resource_path(name):
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


def resource_dir():
    """The persistent folder this program lives in - NOT sys._MEIPASS,
    which is a temporary extraction folder that's gone after the process
    exits. Used for things that need to survive between runs, like
    collected-reports/."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


# --------------------------------------------------------------------------
# Windows admin check / elevation (pure ctypes, no external process)
# --------------------------------------------------------------------------
def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    params = " ".join('"{}"'.format(a) for a in sys.argv[1:])
    exe = sys.executable
    script = os.path.abspath(sys.argv[0])
    if getattr(sys, "frozen", False):
        target, args = exe, params
    else:
        target, args = exe, '"{}" {}'.format(script, params)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", target, args, None, 1)
    sys.exit(0)


# --------------------------------------------------------------------------
# Removable-drive enumeration (pure ctypes, no pywin32 dependency needed)
# --------------------------------------------------------------------------
DRIVE_REMOVABLE = 2


def get_removable_drives():
    drives = []
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for i in range(26):
        if not (bitmask & (1 << i)):
            continue
        letter = string.ascii_uppercase[i]
        root = "{}:\\".format(letter)
        try:
            drive_type = ctypes.windll.kernel32.GetDriveTypeW(root)
        except Exception:
            continue
        if drive_type != DRIVE_REMOVABLE:
            continue

        vol_buf = ctypes.create_unicode_buffer(261)
        fs_buf = ctypes.create_unicode_buffer(261)
        serial = ctypes.c_ulong(0)
        max_len = ctypes.c_ulong(0)
        flags = ctypes.c_ulong(0)
        ok = ctypes.windll.kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(root), vol_buf, 261,
            ctypes.byref(serial), ctypes.byref(max_len),
            ctypes.byref(flags), fs_buf, 261
        )
        label = vol_buf.value if ok else ""
        fs = fs_buf.value if ok else "?"

        total_bytes = ctypes.c_ulonglong(0)
        free_bytes = ctypes.c_ulonglong(0)
        total_free = ctypes.c_ulonglong(0)
        ctypes.windll.kernel32.GetDiskFreeSpaceExW(
            root, ctypes.byref(free_bytes), ctypes.byref(total_bytes), ctypes.byref(total_free)
        )
        size_gb = round(total_bytes.value / (1024 ** 3), 1) if total_bytes.value else 0.0

        drives.append({"letter": letter, "label": label, "fs": fs, "size_gb": size_gb})
    return drives


# --------------------------------------------------------------------------
# Core operations - explicit argument lists only, never a shell string
# --------------------------------------------------------------------------
def run_cmd(args):
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, shell=False,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
        out = (result.stdout or "") + (result.stderr or "")
        return result.returncode, out.strip()
    except FileNotFoundError as e:
        return -1, str(e)


def format_drive_ntfs(letter, label="OTZARIA", log=lambda *_: None):
    """Uses diskpart - the same engine behind Windows' own Disk Management -
    since it is the most reliable option for removable media."""
    script = "select volume {}\nformat fs=ntfs quick label={}\n".format(letter, label)
    tmp_path = os.path.join(tempfile.gettempdir(), "otz_diskpart_{}.txt".format(int(time.time())))
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(script)
    try:
        code, out = run_cmd(["diskpart", "/s", tmp_path])
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
    log(out)
    return code == 0


def lock_drive(letter, log=lambda *_: None):
    path = "{}:\\".format(letter)
    domain = os.environ.get("USERDOMAIN", "")
    user = os.environ.get("USERNAME", "")
    owner = "{}\\{}".format(domain, user) if domain else user

    steps = [
        ["icacls", path, "/inheritance:r"],
        ["icacls", path, "/grant:r", "{}:(OI)(CI)F".format(owner)],
        ["icacls", path, "/grant:r", "Everyone:(OI)(CI)(RX)"],
        ["icacls", path, "/remove", "Users"],
        ["icacls", path, "/remove", "Authenticated Users"],
    ]
    ok = True
    for i, cmd in enumerate(steps):
        code, out = run_cmd(cmd)
        if out:
            log(out)
        if code != 0 and i < 3:
            ok = False
    return ok


def unlock_drive(letter, log=lambda *_: None):
    path = "{}:\\".format(letter)
    code, out = run_cmd(["icacls", path, "/reset", "/T", "/C"])
    if out:
        log(out)
    return code == 0


REPORTS_FOLDER_NAME = "reports"
REPORTS_INCOMING_SUBFOLDER = "incoming"

# How long a file must sit untouched before cleanup will treat it as
# "finished writing" and safe to validate. Guards against reading a file
# while a legitimate write is still in progress (the app's own temp-then-
# rename pattern already avoids this for the final .json, but this is a
# second, independent safety margin against any writer that doesn't).
REPORT_MIN_AGE_SECONDS = 30


def create_reports_folder(letter, log=lambda *_: None):
    """Carves out reports\\incoming\\ on an otherwise-locked drive: a
    quarantine drop zone, not a trusted destination. Nothing that lands
    here is ever read, uploaded, or acted on in place - see
    clean_reports_folder(), which is the only thing that ever touches
    what shows up here, and which validates before doing anything else.

    Everything outside this folder keeps the restrictive ACL set by
    lock_drive() untouched - NTFS permissions are per-object, so a new
    explicit ACE on just this folder does not loosen anything at the
    drive root.

    The permissions here are deliberately a "drop box": any account can
    create new files, but - via the CREATOR OWNER mechanism, the same
    one Windows itself uses for shared drop folders - only the account
    that created a given file can even read, modify, or delete it
    afterward. No account other than that file's own creator, and this
    program's own owner (who already has full access inherited from the
    drive root, untouched by anything here), can see this folder's
    contents at all - not even list what's in it. This does not stop a
    new malicious file from being dropped in (any write access that
    legitimate software can use, malware can use too - Windows ACLs
    identify accounts, not programs, so there is no permission that
    admits a "genuine Otzaria write" while refusing a write from
    anything else running under the same account), but it does stop one
    computer from tampering with, deleting, or even reading a report
    another computer already left there."""
    path = "{}:\\{}\\{}".format(letter, REPORTS_FOLDER_NAME, REPORTS_INCOMING_SUBFOLDER)
    try:
        os.makedirs(path, exist_ok=True)
    except OSError as e:
        log(str(e))
        return False
    steps = [
        # Everyone can create new files/folders in THIS folder - deliberately
        # not (OI), so this does not also become a "modify existing file"
        # grant once inherited onto a file. Deliberately NOT granting Everyone
        # any read/list rights here at all: nothing except the file's own
        # creator (via the CREATOR OWNER grant below) and this drive's owner
        # (via the Full Control already inherited from the drive root) ever
        # needs to read this folder, so no one else gets to - not even to
        # see that a report exists, let alone read its contents.
        ["icacls", path, "/grant", "Everyone:(WD,AD)"],
        # Whoever creates a file/folder gets full control over just that
        # object (Windows substitutes CREATOR OWNER for the real creating
        # account automatically) - needed so the creator can still rename/
        # finish writing their own file, without handing that same power
        # to every other account.
        ["icacls", path, "/grant", "CREATOR OWNER:(OI)(IO)(F)"],
    ]
    ok = True
    for cmd in steps:
        code, out = run_cmd(cmd)
        if out:
            log(out)
        if code != 0:
            ok = False
    return ok


# A legitimate report matches this exactly - see error_reports_manager's
# OutboxReport.fileJson() in Otzaria_Offline_update. Anything that doesn't
# match gets removed by clean_reports_folder(), never trusted or read.
REPORT_MAX_BYTES = 65536  # generous for a small JSON report; not a log dump
REPORT_REQUIRED_FORMAT = "otzaria-report"
REPORT_REQUIRED_VERSION = 1
REPORT_REQUIRED_KEYS = ("report_id", "endpoint", "body")


def _report_file_invalid_reason(full_path):
    """None if the file looks like a genuine, complete report; otherwise a
    short reason string explaining why it doesn't. Schema-level validation
    only - this can rule a file OUT, it can never prove a file is
    authentic, since nothing here distinguishes a legitimate write from a
    well-crafted malicious one. That's a structural limit of file
    permissions, not something a stricter schema check can close; see the
    project summary for the endpoint-allowlist and sandboxing that cover
    the remaining gap on the reading/uploading side."""
    name = os.path.basename(full_path)
    if not name.lower().endswith(".json"):
        return "not a .json file"
    try:
        st = os.stat(full_path)
    except OSError:
        return "unreadable"
    if not stat.S_ISREG(st.st_mode):
        return "not a regular file"
    age_seconds = time.time() - st.st_mtime
    if age_seconds < REPORT_MIN_AGE_SECONDS:
        return "too new - possibly still being written"
    if st.st_size > REPORT_MAX_BYTES:
        return "too large ({} bytes)".format(st.st_size)
    try:
        with open(full_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return "not valid JSON"
    if not isinstance(data, dict):
        return "not a JSON object"
    if data.get("format") != REPORT_REQUIRED_FORMAT or data.get("version") != REPORT_REQUIRED_VERSION:
        return "unexpected format/version"
    for key in REPORT_REQUIRED_KEYS:
        if key not in data:
            return "missing '{}'".format(key)
    return None


def clean_reports_folder(letter, log=lambda *_: None, collected_dir=None):
    """Validates reports\\incoming\\ and, for anything that passes, MOVES
    it off the USB entirely - onto this computer, into collected_dir
    (defaults to a "collected-reports" folder next to this program).
    Anything that doesn't pass is deleted outright. Either way, nothing
    accepted is ever left sitting back in the publicly-writable folder:
    once a report has been vetted, it belongs on the distributor's own
    machine, not on a drive any computer can still write to.

    Runs as the drive owner, so - unlike any other account - this has
    full control even over files it didn't create, which is what makes
    deleting/moving other computers' files here possible at all."""
    incoming = "{}:\\{}\\{}".format(letter, REPORTS_FOLDER_NAME, REPORTS_INCOMING_SUBFOLDER)
    if not os.path.isdir(incoming):
        log("no reports folder yet - nothing to clean")
        return True
    if collected_dir is None:
        collected_dir = os.path.join(resource_dir(), "collected-reports")
    try:
        os.makedirs(collected_dir, exist_ok=True)
    except OSError as e:
        log("could not prepare {}: {}".format(collected_dir, e))
        return False

    moved = 0
    removed = 0
    skipped = 0
    for name in os.listdir(incoming):
        full = os.path.join(incoming, name)
        if not os.path.isfile(full):
            try:
                shutil.rmtree(full)
                removed += 1
                log("removed unexpected item: {}".format(name))
            except OSError as e:
                log("could not remove {}: {}".format(name, e))
            continue
        reason = _report_file_invalid_reason(full)
        if reason == "too new - possibly still being written":
            skipped += 1
            continue
        if reason:
            try:
                os.remove(full)
                removed += 1
                log("removed {} ({})".format(name, reason))
            except OSError as e:
                log("could not remove {}: {}".format(name, e))
            continue
        # Valid - move it off the USB. A collision (same report_id
        # collected before) is resolved by keeping both rather than
        # silently overwriting either copy.
        dest = os.path.join(collected_dir, name)
        if os.path.exists(dest):
            stem, ext = os.path.splitext(name)
            dest = os.path.join(collected_dir, "{}_{}{}".format(stem, int(time.time()), ext))
        try:
            shutil.move(full, dest)
            moved += 1
        except OSError as e:
            log("could not move {}: {}".format(name, e))
    log("cleanup done: moved {}, removed {}, left for next time {}".format(moved, removed, skipped))
    return True


def open_in_explorer(letter):
    os.startfile("{}:\\".format(letter))


# --------------------------------------------------------------------------
# Text strings - plain logical (typed) order. Qt reorders Hebrew for
# display on its own; nothing here needs to be pre-reversed.
# --------------------------------------------------------------------------
STR = {
    "he": {
        "app_title": "נעילת דיסק און קי - אוצריא",
        "app_subtitle": "הכנת דיסק להפצה בטוחה",
        "lang_btn": "English",
        "select_drive": "בחירת דיסק און קי",
        "refresh": "רענון רשימה",
        "no_drives": "לא נמצא דיסק און קי מחובר. חברו דיסק ולחצו רענון.",
        "drive_info": "תווית: {label}   ·   מערכת קבצים: {fs}   ·   גודל: {size} GB",
        "prepare": "הכנת הדיסק",
        "open_drive": "פתיחת הדיסק להעתקת קבצים",
        "format_btn": "פרמוט ל-NTFS",
        "lock_btn": "נעילת הדיסק להפצה",
        "unlock_btn": "שחזור הרשאות רגילות",
        "reports_btn": "יצירת תיקיית דוחות (כתיבה מותרת)",
        "reports_creating": "יוצר תיקיית reports\\incoming עם הרשאת כתיבה...",
        "reports_done": "תיקיית 'reports\\incoming' נוצרה. שום דבר בה לא נקרא או נשלח - היא רק תיבת קבלה שממתינה לניקוי.",
        "reports_failed": "יצירת תיקיית הדוחות נכשלה - בדקו את יומן הפעולות.",
        "clean_reports_btn": "בדיקה והעברת דוחות תקינים",
        "clean_reports_running": "בודק את reports\\incoming: דוחות תקינים עוברים למחשב הזה, השאר נמחק...",
        "clean_reports_done": "הבדיקה הושלמה - פרטים ביומן הפעולות.",
        "log_label": "יומן פעולות",
        "footer": "הנעילה חוסמת כתיבה מכל חשבון פרט לחשבון הזה במחשב זה. מנהל מערכת במחשב אחר עדיין יכול לעקוף את הנעילה. תיקיית 'reports\\incoming' היא יוצאת דופן מכוונת - כל מחשב יכול לכתוב רק אליה, אבל שום דבר בה לא נקרא או נסמך עליו עד שהוא נבדק ועובר למחשב הזה.",
        "confirm_letter_title": "אימות דיסק",
        "confirm_letter_msg": "הקלידו את אות הדיסק הנבחר לאישור (למשל E):",
        "letter_mismatch": "האות שהוקלדה אינה תואמת. הפעולה בוטלה.",
        "confirm_format_title": "אזהרה - מחיקת נתונים",
        "confirm_format_msg": "פעולה זו תמחק את כל תוכן הדיסק! הקלידו בדיוק את המילה מחק כדי להמשיך:",
        "format_word": "מחק",
        "format_cancelled": "הפרמוט בוטל.",
        "formatting": "מפרמט את הדיסק ל-NTFS...",
        "format_done": "הפרמוט הושלם בהצלחה.",
        "format_failed": "הפרמוט נכשל - בדקו את יומן הפעולות.",
        "locking": "נועל את הדיסק...",
        "lock_done": "הדיסק ננעל. רק המשתמש הזה יכול לכתוב אליו.",
        "lock_failed": "הנעילה נכשלה - בדקו את יומן הפעולות.",
        "unlocking": "משחזר הרשאות רגילות...",
        "unlock_done": "ההרשאות שוחזרו לברירת המחדל.",
        "unlock_failed": "השחזור נכשל - בדקו את יומן הפעולות.",
        "no_drive_selected": "יש לבחור דיסק תחילה.",
        "already_ntfs": "הדיסק כבר בפורמט NTFS.",
        "admin_ok": "מריץ עם הרשאות מנהל",
        "admin_bad": "אין הרשאות מנהל - חלק מהפעולות עלולות להיכשל",
        "ok": "אישור",
        "cancel": "ביטול",
    },
    "en": {
        "app_title": "Otzaria USB Lock",
        "app_subtitle": "Prepare a drive for safe distribution",
        "lang_btn": "עברית",
        "select_drive": "Select USB Drive",
        "refresh": "Refresh list",
        "no_drives": "No USB drive found. Plug one in and click Refresh.",
        "drive_info": "Label: {label}   ·   File system: {fs}   ·   Size: {size} GB",
        "prepare": "Prepare Drive",
        "open_drive": "Open drive to copy files",
        "format_btn": "Format to NTFS",
        "lock_btn": "Lock drive for distribution",
        "unlock_btn": "Reset to normal permissions",
        "reports_btn": "Create reports folder (writable)",
        "reports_creating": "Creating reports\\incoming with write access...",
        "reports_done": "'reports\\incoming' created. Nothing in it is ever read or uploaded - it's just a drop zone waiting for cleanup.",
        "reports_failed": "Creating the reports folder failed - check the status log.",
        "clean_reports_btn": "Check and collect valid reports",
        "clean_reports_running": "Checking reports\\incoming: valid reports move to this PC, everything else is deleted...",
        "clean_reports_done": "Check finished - see the status log for details.",
        "log_label": "Status Log",
        "footer": "Locking blocks write access from every account except this one on this PC. A local administrator on another PC can still override the lock. The 'reports\\incoming' folder is a deliberate exception - every computer can write only to it, but nothing there is ever read or trusted until it's been checked and moved to this PC.",
        "confirm_letter_title": "Confirm Drive",
        "confirm_letter_msg": "Type the selected drive letter to confirm (e.g. E):",
        "letter_mismatch": "The letter you typed doesn't match. Action cancelled.",
        "confirm_format_title": "Warning - data will be erased",
        "confirm_format_msg": "This will erase everything on the drive! Type exactly ERASE to continue:",
        "format_word": "ERASE",
        "format_cancelled": "Format cancelled.",
        "formatting": "Formatting drive to NTFS...",
        "format_done": "Format completed successfully.",
        "format_failed": "Format failed - check the status log.",
        "locking": "Locking the drive...",
        "lock_done": "Drive locked. Only this account can write to it.",
        "lock_failed": "Locking failed - check the status log.",
        "unlocking": "Restoring normal permissions...",
        "unlock_done": "Permissions reset to default.",
        "unlock_failed": "Reset failed - check the status log.",
        "no_drive_selected": "Select a drive first.",
        "already_ntfs": "Drive is already NTFS.",
        "admin_ok": "Running as administrator",
        "admin_bad": "Not running as administrator - some actions may fail",
        "ok": "OK",
        "cancel": "Cancel",
    },
}

# --------------------------------------------------------------------------
# Otzaria gold/brown colour tokens (חום זהבהב)
# --------------------------------------------------------------------------
C_PRIMARY = "#8C6A1F"
C_ON_PRIMARY = "#FFFFFF"
C_PRIMARY_SUBTLE = "#F3E6C8"
C_SURFACE = "#FFFCF5"
C_ON_SURFACE = "#3B2A0F"
C_ON_SURFACE_VARIANT = "#6B5730"
C_SURFACE_HIGH = "#F1E6CC"
C_SURFACE_HIGHEST = "#E8D8AE"
C_ERROR = "#A13A1E"
C_ON_ERROR = "#FFFFFF"
C_OUTLINE = "#B69B5E"

STYLESHEET = """
QWidget {{
    background-color: {surface_high};
    color: {on_surface};
    font-family: "Segoe UI";
    font-size: 13px;
}}
QFrame#card {{
    background-color: {surface};
    border: 1px solid {outline};
    border-radius: 16px;
}}
QFrame#topbar {{
    background-color: {surface_highest};
    border: none;
    border-bottom: 1px solid {outline};
}}
QLabel#title {{
    font-size: 16px;
    font-weight: 600;
    color: {on_surface};
}}
QLabel#subtitle {{
    font-size: 11px;
    color: {on_surface_variant};
}}
QLabel#cardHeader {{
    font-size: 12px;
    font-weight: 600;
    color: {on_surface_variant};
}}
QLabel#driveInfo, QLabel#footer, QLabel#adminBadge {{
    font-size: 11px;
    color: {on_surface_variant};
}}
QPushButton {{
    border-radius: 18px;
    padding: 10px 16px;
    font-size: 13px;
    font-weight: 600;
}}
QPushButton#filled {{
    background-color: {primary};
    color: {on_primary};
    border: none;
}}
QPushButton#filled:hover {{ background-color: #9C7A2F; }}
QPushButton#filled:disabled {{ background-color: #C9BFA0; color: #FFFFFF; }}

QPushButton#tonal {{
    background-color: {primary_subtle};
    color: {primary};
    border: none;
}}
QPushButton#tonal:hover {{ background-color: {surface_highest}; }}
QPushButton#tonal:disabled {{ color: #B8A98A; }}

QPushButton#outline {{
    background-color: {surface};
    color: {on_surface};
    border: 1px solid {outline};
}}
QPushButton#outline:hover {{ background-color: {surface_highest}; }}
QPushButton#outline:disabled {{ color: #B8A98A; }}

QPushButton#danger {{
    background-color: {error};
    color: {on_error};
    border: none;
}}
QPushButton#danger:hover {{ background-color: #B54426; }}
QPushButton#danger:disabled {{ background-color: #D9B7A9; color: #FFFFFF; }}

QComboBox {{
    background-color: {surface};
    border: 1px solid {outline};
    border-radius: 8px;
    padding: 8px 10px;
}}
QPlainTextEdit#log {{
    background-color: {on_surface};
    color: #E8D8AE;
    font-family: Consolas, monospace;
    font-size: 11px;
    border-radius: 10px;
    border: none;
}}
QDialog {{
    background-color: {surface};
}}
QLineEdit {{
    border: 1px solid {outline};
    border-radius: 8px;
    padding: 8px;
    background-color: {surface};
}}
""".format(
    surface=C_SURFACE, surface_high=C_SURFACE_HIGH, surface_highest=C_SURFACE_HIGHEST,
    on_surface=C_ON_SURFACE, on_surface_variant=C_ON_SURFACE_VARIANT,
    primary=C_PRIMARY, on_primary=C_ON_PRIMARY, primary_subtle=C_PRIMARY_SUBTLE,
    error=C_ERROR, on_error=C_ON_ERROR, outline=C_OUTLINE,
)


def card_frame():
    f = QFrame()
    f.setObjectName("card")
    return f


class ActionWorker(QThread):
    """Runs a blocking OS operation off the GUI thread. Qt widgets can only
    be touched safely from the main thread, so progress/results come back
    via signals instead of direct calls."""
    log_line = Signal(str)
    finished_ok = Signal(bool)

    def __init__(self, func, args):
        super().__init__()
        self.func = func
        self.args = args

    def run(self):
        ok = self.func(*self.args, log=lambda m: self.log_line.emit(m))
        self.finished_ok.emit(ok)


class ConfirmDialog(QDialog):
    """On-brand modal used for the drive-letter and ERASE confirmations."""

    def __init__(self, parent, title, message, lang):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setFixedSize(420, 200)
        self.setLayoutDirection(Qt.RightToLeft if lang == "he" else Qt.LeftToRight)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)

        msg = QLabel(message)
        msg.setWordWrap(True)
        layout.addWidget(msg)

        self.entry = QLineEdit()
        layout.addWidget(self.entry)
        self.entry.setFocus()

        btn_row = QHBoxLayout()
        ok_btn = QPushButton(STR[lang]["ok"])
        ok_btn.setObjectName("filled")
        cancel_btn = QPushButton(STR[lang]["cancel"])
        cancel_btn.setObjectName("outline")
        ok_btn.clicked.connect(self.accept)
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(ok_btn)
        btn_row.addWidget(cancel_btn)
        layout.addLayout(btn_row)

        self.entry.returnPressed.connect(self.accept)

    @staticmethod
    def ask(parent, title, message, lang):
        dlg = ConfirmDialog(parent, title, message, lang)
        if dlg.exec() == QDialog.Accepted:
            return dlg.entry.text()
        return None


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.lang = "he"
        self.drives = []
        self.selected = None
        self._worker = None

        self.setFixedSize(580, 700)
        try:
            self.setWindowIcon(QIcon(resource_path("otzaria-usb-lock.ico")))
        except Exception:
            pass

        self._build_ui()
        self._apply_lang()
        self._check_admin()
        self.refresh_drives()

    # ---------------- UI construction ----------------
    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Topbar
        top = QFrame()
        top.setObjectName("topbar")
        top_layout = QHBoxLayout(top)
        top_layout.setContentsMargins(18, 14, 18, 14)

        logo = QLabel()
        try:
            pix = QPixmap(resource_path("logo-80.png")).scaled(
                40, 40, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            logo.setPixmap(pix)
        except Exception:
            pass
        top_layout.addWidget(logo)

        title_box = QVBoxLayout()
        self.lbl_title = QLabel()
        self.lbl_title.setObjectName("title")
        self.lbl_subtitle = QLabel()
        self.lbl_subtitle.setObjectName("subtitle")
        title_box.addWidget(self.lbl_title)
        title_box.addWidget(self.lbl_subtitle)
        top_layout.addLayout(title_box)
        top_layout.addStretch()

        self.btn_lang = QPushButton()
        self.btn_lang.setObjectName("outline")
        self.btn_lang.setFixedWidth(90)
        self.btn_lang.clicked.connect(self.toggle_lang)
        top_layout.addWidget(self.btn_lang)

        root.addWidget(top)

        body = QVBoxLayout()
        body.setContentsMargins(20, 14, 20, 14)
        body.setSpacing(12)

        self.lbl_admin = QLabel()
        self.lbl_admin.setObjectName("adminBadge")
        self.lbl_admin.setAlignment(Qt.AlignRight)
        body.addWidget(self.lbl_admin)

        # Drive card
        card1 = card_frame()
        c1 = QVBoxLayout(card1)
        c1.setContentsMargins(16, 14, 16, 14)
        self.lbl_select = QLabel()
        self.lbl_select.setObjectName("cardHeader")
        c1.addWidget(self.lbl_select)

        self.drive_combo = QComboBox()
        self.drive_combo.currentIndexChanged.connect(self._on_drive_change)
        c1.addWidget(self.drive_combo)

        self.lbl_drive_info = QLabel()
        self.lbl_drive_info.setObjectName("driveInfo")
        self.lbl_drive_info.setWordWrap(True)
        c1.addWidget(self.lbl_drive_info)

        self.btn_refresh = QPushButton()
        self.btn_refresh.setObjectName("outline")
        self.btn_refresh.clicked.connect(self.refresh_drives)
        c1.addWidget(self.btn_refresh, alignment=Qt.AlignLeft)
        body.addWidget(card1)

        # Actions card
        card2 = card_frame()
        c2 = QVBoxLayout(card2)
        c2.setContentsMargins(16, 14, 16, 14)
        self.lbl_prepare = QLabel()
        self.lbl_prepare.setObjectName("cardHeader")
        c2.addWidget(self.lbl_prepare)

        row1 = QHBoxLayout()
        self.btn_open = QPushButton()
        self.btn_open.setObjectName("tonal")
        self.btn_open.setEnabled(False)
        self.btn_open.clicked.connect(self.on_open)
        self.btn_format = QPushButton()
        self.btn_format.setObjectName("outline")
        self.btn_format.setEnabled(False)
        self.btn_format.clicked.connect(self.on_format)
        row1.addWidget(self.btn_open)
        row1.addWidget(self.btn_format)
        c2.addLayout(row1)

        row2 = QHBoxLayout()
        self.btn_lock = QPushButton()
        self.btn_lock.setObjectName("filled")
        self.btn_lock.setEnabled(False)
        self.btn_lock.clicked.connect(self.on_lock)
        self.btn_unlock = QPushButton()
        self.btn_unlock.setObjectName("danger")
        self.btn_unlock.setEnabled(False)
        self.btn_unlock.clicked.connect(self.on_unlock)
        row2.addWidget(self.btn_lock)
        row2.addWidget(self.btn_unlock)
        c2.addLayout(row2)

        self.btn_reports = QPushButton()
        self.btn_reports.setObjectName("tonal")
        self.btn_reports.setEnabled(False)
        self.btn_reports.clicked.connect(self.on_reports)
        c2.addWidget(self.btn_reports)

        self.btn_clean_reports = QPushButton()
        self.btn_clean_reports.setObjectName("outline")
        self.btn_clean_reports.setEnabled(False)
        self.btn_clean_reports.clicked.connect(self.on_clean_reports)
        c2.addWidget(self.btn_clean_reports)
        body.addWidget(card2)

        # Log card
        card3 = card_frame()
        c3 = QVBoxLayout(card3)
        c3.setContentsMargins(16, 14, 16, 14)
        self.lbl_log = QLabel()
        self.lbl_log.setObjectName("cardHeader")
        c3.addWidget(self.lbl_log)
        self.txt_log = QPlainTextEdit()
        self.txt_log.setObjectName("log")
        self.txt_log.setReadOnly(True)
        self.txt_log.setLayoutDirection(Qt.LeftToRight)  # command output is English
        c3.addWidget(self.txt_log)
        body.addWidget(card3, stretch=1)

        self.lbl_footer = QLabel()
        self.lbl_footer.setObjectName("footer")
        self.lbl_footer.setWordWrap(True)
        body.addWidget(self.lbl_footer)

        root.addLayout(body)

    # ---------------- language ----------------
    def toggle_lang(self):
        self.lang = "en" if self.lang == "he" else "he"
        self._apply_lang()
        self._render_drive_info()

    def t(self, key):
        return STR[self.lang][key]

    def _apply_lang(self):
        s = STR[self.lang]
        rtl = self.lang == "he"
        self.setLayoutDirection(Qt.RightToLeft if rtl else Qt.LeftToRight)
        self.setWindowTitle(s["app_title"])

        self.lbl_title.setText(s["app_title"])
        self.lbl_subtitle.setText(s["app_subtitle"])
        self.btn_lang.setText(s["lang_btn"])
        self.lbl_select.setText(s["select_drive"])
        self.btn_refresh.setText("🔄  " + s["refresh"])
        self.lbl_prepare.setText(s["prepare"])
        self.btn_open.setText(s["open_drive"])
        self.btn_format.setText(s["format_btn"])
        self.btn_lock.setText("🔒  " + s["lock_btn"])
        self.btn_unlock.setText("↺  " + s["unlock_btn"])
        self.btn_reports.setText("📁  " + s["reports_btn"])
        self.btn_clean_reports.setText("🧹  " + s["clean_reports_btn"])
        self.lbl_log.setText(s["log_label"])
        self.lbl_footer.setText(s["footer"])
        self._check_admin()

    # ---------------- log ----------------
    def log(self, msg):
        if not msg:
            return
        stamp = time.strftime("%H:%M:%S")
        self.txt_log.appendPlainText("[{}] {}".format(stamp, msg))

    # ---------------- admin ----------------
    def _check_admin(self):
        if is_admin():
            self.lbl_admin.setText("✓ " + self.t("admin_ok"))
            self.lbl_admin.setStyleSheet("color: #2E7D32;")
        else:
            self.lbl_admin.setText("⚠ " + self.t("admin_bad"))
            self.lbl_admin.setStyleSheet("color: {};".format(C_ERROR))

    # ---------------- drives ----------------
    def refresh_drives(self):
        self.drives = get_removable_drives()
        self.drive_combo.blockSignals(True)
        self.drive_combo.clear()
        if not self.drives:
            self.drive_combo.addItem(self.t("no_drives"))
            self.drive_combo.blockSignals(False)
            self._set_buttons(False)
            self.selected = None
            self._render_drive_info()
            return
        for d in self.drives:
            self.drive_combo.addItem("{}:  {}".format(d["letter"], d["label"]))
        self.drive_combo.blockSignals(False)
        self.drive_combo.setCurrentIndex(0)
        self.selected = self.drives[0]
        self._set_buttons(True)
        self._render_drive_info()

    def _on_drive_change(self, index):
        if 0 <= index < len(self.drives):
            self.selected = self.drives[index]
        self._render_drive_info()

    def _render_drive_info(self):
        if not self.selected:
            self.lbl_drive_info.setText("")
            return
        self.lbl_drive_info.setText(STR[self.lang]["drive_info"].format(
            label=self.selected["label"] or "-", fs=self.selected["fs"], size=self.selected["size_gb"]))

    def _set_buttons(self, enabled):
        for b in (self.btn_open, self.btn_format, self.btn_lock, self.btn_unlock, self.btn_reports, self.btn_clean_reports):
            b.setEnabled(enabled)

    # ---------------- confirmations ----------------
    def _confirm_letter(self):
        if not self.selected:
            self.log(self.t("no_drive_selected"))
            return False
        typed = ConfirmDialog.ask(self, self.t("confirm_letter_title"), self.t("confirm_letter_msg"), self.lang)
        if typed is None:
            return False
        if typed.strip().rstrip(":").upper() != self.selected["letter"]:
            self.log(self.t("letter_mismatch"))
            return False
        return True

    def _confirm_erase_word(self):
        expected = STR[self.lang]["format_word"]
        typed = ConfirmDialog.ask(self, self.t("confirm_format_title"), self.t("confirm_format_msg"), self.lang)
        if typed is None or typed.strip() != expected:
            self.log(self.t("format_cancelled"))
            return False
        return True

    # ---------------- actions ----------------
    def on_open(self):
        if not self.selected:
            self.log(self.t("no_drive_selected"))
            return
        try:
            open_in_explorer(self.selected["letter"])
        except Exception as e:
            self.log(str(e))

    def on_format(self):
        if not self.selected:
            self.log(self.t("no_drive_selected"))
            return
        if self.selected["fs"] == "NTFS":
            self.log(self.t("already_ntfs"))
            return
        if not self._confirm_letter():
            return
        if not self._confirm_erase_word():
            return
        letter = self.selected["letter"]
        self._set_buttons(False)
        self.log(self.t("formatting"))

        def on_done(ok):
            self.log(self.t("format_done") if ok else self.t("format_failed"))
            self.refresh_drives()

        self._worker = ActionWorker(format_drive_ntfs, (letter, "OTZARIA"))
        self._worker.log_line.connect(self.log)
        self._worker.finished_ok.connect(on_done)
        self._worker.start()

    def on_lock(self):
        if not self._confirm_letter():
            return
        letter = self.selected["letter"]
        self._set_buttons(False)
        self.log(self.t("locking"))

        def on_done(ok):
            self.log(self.t("lock_done") if ok else self.t("lock_failed"))
            self._set_buttons(True)

        self._worker = ActionWorker(lock_drive, (letter,))
        self._worker.log_line.connect(self.log)
        self._worker.finished_ok.connect(on_done)
        self._worker.start()

    def on_unlock(self):
        if not self._confirm_letter():
            return
        letter = self.selected["letter"]
        self._set_buttons(False)
        self.log(self.t("unlocking"))

        def on_done(ok):
            self.log(self.t("unlock_done") if ok else self.t("unlock_failed"))
            self._set_buttons(True)

        self._worker = ActionWorker(unlock_drive, (letter,))
        self._worker.log_line.connect(self.log)
        self._worker.finished_ok.connect(on_done)
        self._worker.start()

    def on_reports(self):
        if not self._confirm_letter():
            return
        letter = self.selected["letter"]
        self._set_buttons(False)
        self.log(self.t("reports_creating"))

        def on_done(ok):
            self.log(self.t("reports_done") if ok else self.t("reports_failed"))
            self._set_buttons(True)

        self._worker = ActionWorker(create_reports_folder, (letter,))
        self._worker.log_line.connect(self.log)
        self._worker.finished_ok.connect(on_done)
        self._worker.start()

    def on_clean_reports(self):
        if not self.selected:
            self.log(self.t("no_drive_selected"))
            return
        letter = self.selected["letter"]
        self._set_buttons(False)
        self.log(self.t("clean_reports_running"))

        def on_done(ok):
            self.log(self.t("clean_reports_done"))
            self._set_buttons(True)

        self._worker = ActionWorker(clean_reports_folder, (letter,))
        self._worker.log_line.connect(self.log)
        self._worker.finished_ok.connect(on_done)
        self._worker.start()


def main():
    if os.name != "nt":
        print("This tool only runs on Windows.")
        sys.exit(1)
    if not is_admin():
        relaunch_as_admin()
        return

    app = QApplication(sys.argv)
    app.setStyleSheet(STYLESHEET)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
