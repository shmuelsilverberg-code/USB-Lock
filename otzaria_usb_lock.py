# -*- coding: utf-8 -*-
"""
Otzaria USB Lock
-----------------
Prepares a USB drive for safe distribution: formats it to NTFS and locks
write access so that only the current Windows account can write to it.
Every other computer can only read/execute from it, which blocks the main
way flash-drive malware spreads (writing a copy of itself to any writable
removable drive it finds).

Built with: Python + customtkinter, compiled to a single .exe with PyInstaller.
No shell strings are built anywhere - every OS command is called with an
explicit argument list, so there is no quoting for Windows to misparse.
"""

import os
import sys
import ctypes
import string
import tempfile
import subprocess
import threading
import time

import customtkinter as ctk
from PIL import Image

try:
    from bidi.algorithm import get_display
    _BIDI_OK = True
except Exception:
    _BIDI_OK = False


def rtl(text, lang):
    """Tkinter draws text in logical (typed) order and has no built-in
    Unicode Bidi Algorithm, so Hebrew comes out reading left-to-right
    unless we reorder it ourselves first. python-bidi does that reordering
    (and handles strings that mix Hebrew with numbers/English correctly)."""
    if lang == "he" and _BIDI_OK and text:
        try:
            return get_display(text)
        except Exception:
            return text
    return text


# --------------------------------------------------------------------------
# Resource path helper (works both as a plain .py and as a PyInstaller .exe)
# --------------------------------------------------------------------------
def resource_path(name):
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


# --------------------------------------------------------------------------
# Windows admin check (no external process - pure ctypes)
# --------------------------------------------------------------------------
def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    """Re-launches this same exe/script elevated, then exits the current one."""
    params = " ".join('"{}"'.format(a) for a in sys.argv[1:])
    exe = sys.executable
    script = os.path.abspath(sys.argv[0])
    if getattr(sys, "frozen", False):
        # Running as a compiled exe - relaunch the exe itself
        target, args = exe, params
    else:
        # Running as a plain script under python.exe
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
# Core operations - every command is an explicit argument list, never a
# shell string, so there is nothing for cmd.exe to misinterpret.
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


def open_in_explorer(letter):
    os.startfile("{}:\\".format(letter))


# --------------------------------------------------------------------------
# Text strings (Hebrew default, English toggle)
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
        "log_label": "יומן פעולות",
        "footer": "הנעילה חוסמת כתיבה מכל חשבון פרט לחשבון הזה במחשב זה.",
        "confirm_letter_title": "אימות דיסק",
        "confirm_letter_msg": "הקלידו את אות הדיסק הנבחר לאישור (למשל E):",
        "letter_mismatch": "האות שהוקלדה אינה תואמת. הפעולה בוטלה.",
        "confirm_format_title": "אזהרה - מחיקת נתונים",
        "confirm_format_msg": "פעולה זו תמחק את כל תוכן הדיסק! הקלידו בדיוק את המילה הבאה כדי להמשיך:",
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
        "log_label": "Status Log",
        "footer": "Locking blocks write access from every account except this one on this PC. A local administrator on another PC can still override the lock.",
        "confirm_letter_title": "Confirm Drive",
        "confirm_letter_msg": "Type the selected drive letter to confirm (e.g. E):",
        "letter_mismatch": "The letter you typed doesn't match. Action cancelled.",
        "confirm_format_title": "Warning - data will be erased",
        "confirm_format_msg": "This will erase everything on the drive! Type exactly the word below to continue:",
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
# Otzaria gold/brown colour tokens (חום זהבהב) - sampled from the app icon's
# own gold gradient rather than the app's generic purple M3 palette
# --------------------------------------------------------------------------
C_PRIMARY = "#8C6A1F"            # golden-brown - buttons, accents
C_ON_PRIMARY = "#FFFFFF"
C_PRIMARY_SUBTLE = "#F3E6C8"     # light gold tint - tonal button fill
C_SURFACE = "#FFFCF5"            # warm off-white - cards
C_ON_SURFACE = "#3B2A0F"         # dark brown - main text
C_ON_SURFACE_VARIANT = "#6B5730" # medium gold-brown - secondary text
C_SURFACE_HIGH = "#F1E6CC"       # warm beige - window background
C_SURFACE_HIGHEST = "#E8D8AE"    # deeper beige - hover/secondary bg
C_ERROR = "#A13A1E"              # warm brick red - stays recognizable as "danger"
C_ON_ERROR = "#FFFFFF"
C_OUTLINE = "#B69B5E"            # gold-brown outline/border

ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")  # overridden per-widget below


class ConfirmDialog(ctk.CTkToplevel):
    """Small on-brand modal used for the drive-letter and ERASE confirmations."""

    def __init__(self, master, title, message, expected_word, lang):
        super().__init__(master)
        self.result = None
        self.expected_word = expected_word
        self.lang = lang
        self.title(title)
        self.geometry("420x260")
        self.resizable(False, False)
        self.configure(fg_color=C_SURFACE)
        self.transient(master)
        self.grab_set()

        anchor = "e" if lang == "he" else "w"
        justify = "right" if lang == "he" else "left"

        ctk.CTkLabel(self, text=message, wraplength=370, justify=justify,
                     text_color=C_ON_SURFACE, font=("Segoe UI", 13)).pack(padx=20, pady=(24, 10), anchor=anchor)

        # The word to type - in BOLD
        if expected_word:
            word_frame = ctk.CTkFrame(self, fg_color="transparent")
            word_frame.pack(pady=(0, 10), anchor=anchor)
            ctk.CTkLabel(word_frame, text=rtl(expected_word, lang), 
                         text_color=C_PRIMARY, font=("Segoe UI", 14, "bold")).pack()

        self.entry = ctk.CTkEntry(self, width=360, justify=justify)
        self.entry.pack(padx=20, pady=6)
        self.entry.focus()

        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(pady=18)
        ctk.CTkButton(btn_row, text=rtl(STR[lang]["ok"], lang), fg_color=C_PRIMARY, hover_color=C_PRIMARY,
                      corner_radius=18, width=110, command=self._ok).pack(side="left", padx=8)
        ctk.CTkButton(btn_row, text=rtl(STR[lang]["cancel"], lang), fg_color=C_SURFACE_HIGHEST, text_color=C_ON_SURFACE,
                      hover_color=C_SURFACE_HIGH, corner_radius=18, width=110, command=self._cancel).pack(side="left", padx=8)

        self.bind("<Return>", lambda e: self._ok())
        self.bind("<Escape>", lambda e: self._cancel())
        self.protocol("WM_DELETE_WINDOW", self._cancel)

    def _ok(self):
        self.result = self.entry.get()
        self.destroy()

    def _cancel(self):
        self.result = None
        self.destroy()

    @staticmethod
    def ask(master, title, message, expected_word, lang):
        dlg = ConfirmDialog(master, title, message, expected_word, lang)
        master.wait_window(dlg)
        return dlg.result


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.lang = "he"
        self.drives = []
        self.selected = None

        self.title(STR[self.lang]["app_title"])
        self.geometry("560x680")
        self.configure(fg_color=C_SURFACE_HIGH)
        self.resizable(False, False)

        try:
            self.iconbitmap(resource_path("otzaria-usb-lock.ico"))
        except Exception:
            pass

        self._build_ui()
        self._apply_lang()
        self._check_admin()
        self.refresh_drives()

    # ---------------- UI construction ----------------
    def _build_ui(self):
        # Topbar
        top = ctk.CTkFrame(self, fg_color=C_SURFACE_HIGHEST, corner_radius=0, height=76)
        top.pack(fill="x")
        top.pack_propagate(False)

        try:
            logo_img = Image.open(resource_path("logo-80.png"))
            self.logo_ctk = ctk.CTkImage(light_image=logo_img, size=(40, 40))
            ctk.CTkLabel(top, image=self.logo_ctk, text="").pack(side="left", padx=(18, 10), pady=16)
        except Exception:
            pass

        title_box = ctk.CTkFrame(top, fg_color="transparent")
        title_box.pack(side="left", pady=10)
        self.lbl_title = ctk.CTkLabel(title_box, text="", font=("Segoe UI", 16, "bold"), text_color=C_ON_SURFACE)
        self.lbl_title.pack(anchor="w")
        self.lbl_subtitle = ctk.CTkLabel(title_box, text="", font=("Segoe UI", 11), text_color=C_ON_SURFACE_VARIANT)
        self.lbl_subtitle.pack(anchor="w")

        self.btn_lang = ctk.CTkButton(top, text="", width=90, corner_radius=16,
                                       fg_color=C_SURFACE, text_color=C_PRIMARY, hover_color=C_PRIMARY_SUBTLE,
                                       border_width=1, border_color=C_OUTLINE, command=self.toggle_lang)
        self.btn_lang.pack(side="right", padx=18)

        # Admin badge
        self.lbl_admin = ctk.CTkLabel(self, text="", font=("Segoe UI", 11), text_color=C_ON_SURFACE_VARIANT)
        self.lbl_admin.pack(anchor="e", padx=20, pady=(10, 0))

        # Drive card
        card1 = ctk.CTkFrame(self, fg_color=C_SURFACE, corner_radius=16, border_width=1, border_color=C_OUTLINE)
        card1.pack(fill="x", padx=20, pady=(10, 12))
        self.lbl_select = ctk.CTkLabel(card1, text="", font=("Segoe UI", 12, "bold"), text_color=C_ON_SURFACE_VARIANT)
        self.lbl_select.pack(anchor="w", padx=16, pady=(14, 4))

        self.drive_var = ctk.StringVar(value="")
        self.drive_menu = ctk.CTkOptionMenu(card1, variable=self.drive_var, values=[""], command=self._on_drive_change,
                                             fg_color=C_SURFACE, text_color=C_ON_SURFACE, button_color=C_PRIMARY,
                                             button_hover_color=C_PRIMARY, dropdown_fg_color=C_SURFACE, width=480)
        self.drive_menu.pack(padx=16, pady=4, fill="x")

        self.lbl_drive_info = ctk.CTkLabel(card1, text="", font=("Segoe UI", 11), text_color=C_ON_SURFACE_VARIANT, justify="left")
        self.lbl_drive_info.pack(anchor="w", padx=16, pady=(4, 4))

        self.btn_refresh = ctk.CTkButton(card1, text="", corner_radius=18, fg_color=C_SURFACE_HIGHEST,
                                          text_color=C_ON_SURFACE, hover_color=C_SURFACE_HIGH,
                                          border_width=1, border_color=C_OUTLINE, command=self.refresh_drives)
        self.btn_refresh.pack(anchor="w", padx=16, pady=(0, 14))

        # Actions card
        card2 = ctk.CTkFrame(self, fg_color=C_SURFACE, corner_radius=16, border_width=1, border_color=C_OUTLINE)
        card2.pack(fill="x", padx=20, pady=(0, 12))
        self.lbl_prepare = ctk.CTkLabel(card2, text="", font=("Segoe UI", 12, "bold"), text_color=C_ON_SURFACE_VARIANT)
        self.lbl_prepare.pack(anchor="w", padx=16, pady=(14, 8))

        row1 = ctk.CTkFrame(card2, fg_color="transparent")
        row1.pack(fill="x", padx=16)
        self.btn_open = ctk.CTkButton(row1, text="", corner_radius=18, fg_color=C_PRIMARY_SUBTLE, text_color=C_PRIMARY,
                                       hover_color=C_SURFACE_HIGH, state="disabled", command=self.on_open)
        self.btn_open.pack(side="left", expand=True, fill="x", padx=(0, 6), pady=4)
        self.btn_format = ctk.CTkButton(row1, text="", corner_radius=18, fg_color=C_SURFACE, text_color=C_ON_SURFACE,
                                         hover_color=C_SURFACE_HIGH, border_width=1, border_color=C_OUTLINE,
                                         state="disabled", command=self.on_format)
        self.btn_format.pack(side="left", expand=True, fill="x", padx=(6, 0), pady=4)

        row2 = ctk.CTkFrame(card2, fg_color="transparent")
        row2.pack(fill="x", padx=16, pady=(6, 16))
        self.btn_lock = ctk.CTkButton(row2, text="", corner_radius=18, fg_color=C_PRIMARY, text_color=C_ON_PRIMARY,
                                       hover_color=C_PRIMARY, state="disabled", command=self.on_lock)
        self.btn_lock.pack(side="left", expand=True, fill="x", padx=(0, 6), pady=4)
        self.btn_unlock = ctk.CTkButton(row2, text="", corner_radius=18, fg_color=C_ERROR, text_color=C_ON_ERROR,
                                         hover_color=C_ERROR, state="disabled", command=self.on_unlock)
        self.btn_unlock.pack(side="left", expand=True, fill="x", padx=(6, 0), pady=4)

        # Log card
        card3 = ctk.CTkFrame(self, fg_color=C_SURFACE, corner_radius=16, border_width=1, border_color=C_OUTLINE)
        card3.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        self.lbl_log = ctk.CTkLabel(card3, text="", font=("Segoe UI", 12, "bold"), text_color=C_ON_SURFACE_VARIANT)
        self.lbl_log.pack(anchor="w", padx=16, pady=(14, 6))
        self.txt_log = ctk.CTkTextbox(card3, fg_color=C_ON_SURFACE, text_color="#E8D8AE", font=("Consolas", 11),
                                       corner_radius=10)
        self.txt_log.pack(fill="both", expand=True, padx=16, pady=(0, 14))
        self.txt_log.configure(state="disabled")

        self.lbl_footer = ctk.CTkLabel(self, text="", font=("Segoe UI", 10), text_color=C_ON_SURFACE_VARIANT,
                                        wraplength=520, justify="left")
        self.lbl_footer.pack(padx=20, pady=(0, 14))

    # ---------------- language ----------------
    def toggle_lang(self):
        self.lang = "en" if self.lang == "he" else "he"
        self._apply_lang()
        self._render_drive_info()

    def t(self, key):
        """Look up a string in the current language and reorder it for
        correct right-to-left display when needed."""
        return rtl(STR[self.lang][key], self.lang)

    def _apply_lang(self):
        self.title(self.t("app_title"))
        self.lbl_title.configure(text=self.t("app_title"))
        self.lbl_subtitle.configure(text=self.t("app_subtitle"))
        self.btn_lang.configure(text=self.t("lang_btn"))
        self.lbl_select.configure(text=self.t("select_drive"))
        self.btn_refresh.configure(text="🔄 " + self.t("refresh"))
        self.lbl_prepare.configure(text=self.t("prepare"))
        self.btn_open.configure(text=self.t("open_drive"))
        self.btn_format.configure(text=self.t("format_btn"))
        self.btn_lock.configure(text="🔒 " + self.t("lock_btn"))
        self.btn_unlock.configure(text="↺ " + self.t("unlock_btn"))
        self.lbl_log.configure(text=self.t("log_label"))
        self.lbl_footer.configure(text=self.t("footer"))
        anchor = "e" if self.lang == "he" else "w"
        just = "right" if self.lang == "he" else "left"
        for w in (self.lbl_title, self.lbl_subtitle, self.lbl_select, self.lbl_prepare, self.lbl_log):
            w.configure(anchor=anchor)
        self.lbl_footer.configure(justify=just)
        self._check_admin()

    # ---------------- log ----------------
    def log(self, msg):
        if not msg:
            return
        self.after(0, lambda: self._log_to_widget(msg))

    def _log_to_widget(self, msg):
        self.txt_log.configure(state="normal")
        stamp = time.strftime("%H:%M:%S")
        self.txt_log.insert("end", "[{}] {}\n".format(stamp, msg))
        self.txt_log.see("end")
        self.txt_log.configure(state="disabled")

    # ---------------- admin ----------------
    def _check_admin(self):
        if is_admin():
            self.lbl_admin.configure(text="✓ " + self.t("admin_ok"), text_color="#2E7D32")
        else:
            self.lbl_admin.configure(text="⚠ " + self.t("admin_bad"), text_color=C_ERROR)

    # ---------------- drives ----------------
    def refresh_drives(self):
        self.drives = get_removable_drives()
        if not self.drives:
            no_drives = self.t("no_drives")
            self.drive_menu.configure(values=[no_drives])
            self.drive_var.set(no_drives)
            self._set_buttons(False)
            self.selected = None
            self._render_drive_info()
            return
        labels = ["{}:  {}".format(d["letter"], d["label"]) for d in self.drives]
        self.drive_menu.configure(values=labels)
        self.drive_var.set(labels[0])
        self.selected = self.drives[0]
        self._set_buttons(True)
        self._render_drive_info()

    def _on_drive_change(self, value):
        for d in self.drives:
            if value.startswith(d["letter"] + ":"):
                self.selected = d
                break
        self._render_drive_info()

    def _render_drive_info(self):
        if not self.selected:
            self.lbl_drive_info.configure(text="")
            return
        text = STR[self.lang]["drive_info"].format(
            label=self.selected["label"] or "-", fs=self.selected["fs"], size=self.selected["size_gb"])
        self.lbl_drive_info.configure(text=rtl(text, self.lang))

    def _set_buttons(self, enabled):
        state = "normal" if enabled else "disabled"
        for b in (self.btn_open, self.btn_format, self.btn_lock, self.btn_unlock):
            b.configure(state=state)

    # ---------------- confirmations ----------------
    def _confirm_letter(self):
        if not self.selected:
            self.log(self.t("no_drive_selected"))
            return False
        typed = ConfirmDialog.ask(self, self.t("confirm_letter_title"), self.t("confirm_letter_msg"),
                                  self.selected["letter"], self.lang)
        if typed is None:
            return False
        if typed.strip().rstrip(":").upper() != self.selected["letter"]:
            self.log(self.t("letter_mismatch"))
            return False
        return True

    def _confirm_erase_word(self):
        # Compare against the RAW word (not bidi-reordered) - the entry box
        # holds what the user actually typed, in logical order.
        expected = STR[self.lang]["format_word"]
        typed = ConfirmDialog.ask(self, self.t("confirm_format_title"), self.t("confirm_format_msg"),
                                  expected, self.lang)
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

        def work():
            ok = format_drive_ntfs(letter, "OTZARIA", log=self.log)
            self.log(self.t("format_done") if ok else self.t("format_failed"))
            self.after(0, self.refresh_drives)

        threading.Thread(target=work, daemon=True).start()

    def on_lock(self):
        if not self._confirm_letter():
            return
        letter = self.selected["letter"]
        self._set_buttons(False)
        self.log(self.t("locking"))

        def work():
            ok = lock_drive(letter, log=self.log)
            self.log(self.t("lock_done") if ok else self.t("lock_failed"))
            self.after(0, lambda: self._set_buttons(True))

        threading.Thread(target=work, daemon=True).start()

    def on_unlock(self):
        if not self._confirm_letter():
            return
        letter = self.selected["letter"]
        self._set_buttons(False)
        self.log(self.t("unlocking"))

        def work():
            ok = unlock_drive(letter, log=self.log)
            self.log(self.t("unlock_done") if ok else self.t("unlock_failed"))
            self.after(0, lambda: self._set_buttons(True))

        threading.Thread(target=work, daemon=True).start()


def main():
    if os.name != "nt":
        print("This tool only runs on Windows.")
        sys.exit(1)
    if not is_admin():
        relaunch_as_admin()
        return
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
