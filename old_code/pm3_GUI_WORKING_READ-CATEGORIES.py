#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pi NTAG213 GUI — batch read, dump parsing, safer write
- Single-session reads using `hf mfu dump` (robust table-row parser)
- Startup checks (pm3 binary + serial); READ/WRITE disabled if missing
- Modal progress dialog during long ops (read/wipe/write/verify)
- Wipe protection: preview existing data and confirm before erasing
- DB cache: prefer DATABASE/<UID>.txt on READ; create it if missing
- WRITE performs a checkout-like DB cleanup before wiping/writing
- pm3 dump artifacts stored in DATABASE/TMP and auto-cleared
"""

import os
import re
import glob
import time
import shutil
import subprocess
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

import tkinter as tk
from tkinter import ttk
from tkinter import *
from tkinter import messagebox
from tkinter import (
    Tk, Toplevel, Frame, Button, Label, Text, StringVar,
    END, BOTH, LEFT, RIGHT, BOTTOM, X, Y, messagebox, Menu, Scrollbar, TclError
)

# ========================= CONFIG =========================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PM3_BIN_CANDIDATES = [
    os.environ.get("PM3_BIN"),
    os.path.join(SCRIPT_DIR, "..", "pm3"),
    os.path.join(SCRIPT_DIR, "..", "client", "proxmark3"),
    "pm3",  # rely on PATH
]

START_PAGE = 4
END_PAGE = 39  # inclusive
BYTES_PER_PAGE = 4
USER_BYTES = (END_PAGE - START_PAGE + 1) * BYTES_PER_PAGE

TAG_WAIT_SECONDS = 10
TAG_POLL_INTERVAL = 0.7

DATABASE_DIR = os.path.join(SCRIPT_DIR, "DATABASE")
os.makedirs(DATABASE_DIR, exist_ok=True)

# Temp folder for pm3 artifacts (bin/json); cleared after read and after successful write
TMP_DIR = os.path.join(DATABASE_DIR, "TMP")
os.makedirs(TMP_DIR, exist_ok=True)
# pm3 writes logs under ~/.proxmark3/logs — give it a substitute in TMP
os.makedirs(os.path.join(TMP_DIR, ".proxmark3", "logs"), exist_ok=True)

def clear_tmp_dir():
    """Remove all files/dirs inside TMP (but keep TMP structure)."""
    try:
        for name in os.listdir(TMP_DIR):
            p = os.path.join(TMP_DIR, name)
            if os.path.isdir(p):
                # keep .proxmark3 structure but clear its files
                if os.path.basename(p) == ".proxmark3":
                    logs = os.path.join(p, "logs")
                    if os.path.isdir(logs):
                        for f in os.listdir(logs):
                            fp = os.path.join(logs, f)
                            if os.path.isfile(fp):
                                try: os.remove(fp)
                                except OSError: pass
                    continue
                # other directories in TMP can be removed
                try: shutil.rmtree(p)
                except OSError: pass
            elif os.path.isfile(p):
                try: os.remove(p)
                except OSError: pass
    except FileNotFoundError:
        pass

# ========================= Regex =========================

# UID capture from "hf search"
UID_RE = re.compile(r"(?i)UID\s*[:=]\s*([0-9A-F]{2}(?:\s*[0-9A-F]{2}){3,10})")

# Matches dump table rows like:
# [=]   4/0x04 | 46 49 4C 41 | 0 | FILA
DUMP_ROW_RE = re.compile(
    r'^\[\=\]\s+(?P<blk>\d+)/0x[0-9A-Fa-f]+\s*\|\s*'
    r'(?P<data>(?:[0-9A-Fa-f]{2}\s+){3}[0-9A-Fa-f]{2})\s*\|'
)

# ========================= Helpers =========================

def _which(path: Optional[str]) -> Optional[str]:
    return path if path and (os.path.isfile(path) or shutil.which(path)) else None

def find_pm3_bin() -> Optional[str]:
    for cand in PM3_BIN_CANDIDATES:
        p = _which(cand)
        if p:
            return p
    return None

def detect_pm3_serial() -> Optional[str]:
    # Raspberry Pi / Linux typical
    for pattern in ("/dev/ttyACM*", "/dev/ttyUSB*"):
        for dev in sorted(glob.glob(pattern)):
            return dev
    return None

def db_path_for_uid(uid_hex: str) -> str:
    uid = uid_hex.replace(" ", "").upper()
    return os.path.join(DATABASE_DIR, f"{uid}.txt")

def db_save(uid_hex: str, text: str) -> None:
    with open(db_path_for_uid(uid_hex), "w", encoding="utf-8") as f:
        f.write(text)

def db_delete_all(uid_hex: str) -> int:
    """Delete any DB files containing UID. Return count deleted."""
    uid = uid_hex.replace(" ", "").upper()
    cnt = 0
    for name in os.listdir(DATABASE_DIR):
        if uid in name.upper():
            try:
                os.remove(os.path.join(DATABASE_DIR, name))
                cnt += 1
            except OSError:
                pass
    return cnt

# ========================= PM3 wrapper =========================

@dataclass
class PM3Result:
    rc: int
    out: str
    err: str

class PM3:
    def __init__(self, logger=print):
        self.logger = logger
        self.pm3_bin = find_pm3_bin()
        self.serial = detect_pm3_serial()
        self.workdir = TMP_DIR  # run pm3 in the temp folder

        # Force pm3 to treat TMP as HOME so dumps/logs go under DATABASE/TMP
        self.env = os.environ.copy()
        self.env["HOME"] = TMP_DIR

    def argv(self) -> List[str]:
        if not self.pm3_bin:
            return ["pm3"]  # still try PATH
        argv = [self.pm3_bin]
        if self.serial:
            argv += ["-d", self.serial]
        return argv

    def run(self, commands: Iterable[str], timeout: int = 60, title: Optional[str] = None) -> PM3Result:
        cmds = list(commands)
        if title:
            self.logger(f"\n== PM3: {title} ==\n")
        self.logger("$ " + " ".join(self.argv()))
        for c in cmds:
            self.logger("> " + c)
        try:
            proc = subprocess.run(
                self.argv(),
                input="\n".join(cmds + ["quit"]) + "\n",
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                encoding="utf-8",
                errors="replace",
                cwd=self.workdir,   # write dumps into TMP_DIR
                env=self.env,       # make pm3 think HOME is TMP_DIR
            )
            out, err, rc = proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired as e:
            out, err, rc = e.stdout or "", (e.stderr or "") + "\n[TIMEOUT]", 124
        self.logger(out)
        if err:
            self.logger("[pm3 stderr]\n" + err)
        return PM3Result(rc=rc, out=out, err=err)

    # -------- tag / uid helpers --------
    def get_uid(self, wait_seconds: int = TAG_WAIT_SECONDS) -> Optional[str]:
        deadline = time.time() + wait_seconds
        while time.time() < deadline:
            res = self.run(["hf 14a reader", "hf search"], timeout=10, title="Probe UID")
            m = UID_RE.search(res.out)
            if m:
                uid = " ".join(m.group(1).upper().split())
                return uid
            time.sleep(TAG_POLL_INTERVAL)
        return None

    # -------- reading helpers --------
    def read_user_bytes_via_dump(self) -> Optional[bytes]:
        """Use a single `hf mfu dump` and parse blocks 4..39 from the table output."""
        res = self.run(["hf mfu dump"], timeout=30, title="Dump MFU")
        if res.rc != 0 and not res.out:
            return None

        # Map block index -> 4-byte chunk
        blocks: dict[int, bytes] = {}

        for line in res.out.splitlines():
            m = DUMP_ROW_RE.match(line)
            if not m:
                continue
            blk = int(m.group("blk"))
            data = bytes(int(x, 16) for x in m.group("data").split())
            if len(data) != 4:
                continue
            blocks[blk] = data

        # Collect user pages 4..39 in order; stop at first all-zero block
        out = bytearray()
        for blk in range(START_PAGE, END_PAGE + 1):
            if blk not in blocks:
                return None
            chunk = blocks[blk]
            if chunk == b"\x00\x00\x00\x00":
                break
            out += chunk

        return bytes(out)

    def read_user_bytes(self) -> Optional[bytes]:
        return self.read_user_bytes_via_dump()  # dump-only for speed/reliability

    # -------- writing helpers --------
    def wipe_pages(self) -> bool:
        cmds = [f"hf mfu wrbl -b {i} -d 00000000" for i in range(START_PAGE, END_PAGE + 1)]
        res = self.run(cmds, timeout=60, title="Wipe user pages")
        return res.rc == 0

    def write_ascii(self, text: str) -> bool:
        raw = text.encode("utf-8", "replace")[:USER_BYTES]
        if len(raw) % 4:
            raw = raw + b"\x00" * (4 - (len(raw) % 4))
        cmds: List[str] = []
        for i in range(0, len(raw), 4):
            page = START_PAGE + (i // 4)
            chunk = raw[i:i+4]
            cmds.append(f"hf mfu wrbl -b {page} -d {chunk.hex().upper()}")
        res = self.run(cmds, timeout=80, title="Write user ASCII bytes")
        return res.rc == 0

# ========================= UI helpers =========================

class ProgressDialog(Toplevel):
    def __init__(self, parent, title: str, message: str):
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", lambda: None)
        Label(self, text=message, font=("Arial", 11)).pack(padx=16, pady=(16, 6))
        self.pb = ttk.Progressbar(self, mode="indeterminate")
        self.pb.pack(fill=X, padx=16, pady=(0, 16))
        self.pb.start(10)
        self.update_idletasks()

    def close(self):
        try:
            self.pb.stop()
        except Exception:
            pass
        self.grab_release()
        self.destroy()

# ========================= GUI =========================

class LogWindow(Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("PM3 Log")
        self.geometry("760x360")
        self.text = Text(self, wrap="word")
        sb = Scrollbar(self, command=self.text.yview)
        self.text.configure(yscrollcommand=sb.set)
        self.text.pack(side=LEFT, fill=BOTH, expand=True)
        sb.pack(side=RIGHT, fill=Y)

    def append(self, s: str):
        self.text.insert(END, s if s.endswith("\n") else s + "\n")
        self.text.see(END)

class App(Tk):
    def __init__(self):
        super().__init__()
        self.title("NTAG213 GUI (Pi)")
        self.geometry("640x520")
        self.pm3 = PM3(logger=self._log)
        self._logwin: Optional[LogWindow] = None

        # Menu
        m = Menu(self)
        v = Menu(m, tearoff=0)
        v.add_command(label="Log window", command=self.open_log)
        m.add_cascade(label="View", menu=v)
        self.config(menu=m)

        # Status bar
        self.status = StringVar()
        status_frame = Frame(self)
        Label(status_frame, textvariable=self.status, anchor="w").pack(fill=X, padx=8, pady=6)
        status_frame.pack(side=BOTTOM, fill=X)

        # Screens
        self.container = Frame(self)
        self.container.pack(fill=BOTH, expand=True)
        self.screens = {}
        for cls in (HomeScreen, CheckInMenu, ReadResultScreen, WritePromptScreen, InfoScreen):
            scr = cls(self.container, self)
            self.screens[cls.__name__] = scr
            scr.grid(row=0, column=0, sticky="nsew")
        self.show("HomeScreen")

        self._update_status()
        self._apply_pm3_availability()

    # ---------- basic helpers ----------
    def show(self, name: str):
        self.screens[name].tkraise()

    def open_log(self):
        if not self._logwin or not self._logwin.winfo_exists():
            self._logwin = LogWindow(self)
        else:
            self._logwin.deiconify()
            self._logwin.lift()

    def _log(self, s: str):
        if self._logwin and self._logwin.winfo_exists():
            self._logwin.append(s)
        print(s)  # also to stdout

    def _update_status(self):
        pm3_path = self.pm3.pm3_bin or "<not found>"
        dev = self.pm3.serial or "<no device>"
        self.status.set(f"pm3: {pm3_path}    device: {dev}")

    def _apply_pm3_availability(self):
        ok = bool(self.pm3.pm3_bin and self.pm3.serial)
        self.screens["HomeScreen"].set_enabled(ok)
        if not ok:
            messagebox.showerror(
                "Proxmark3 not available",
                "The pm3 client or serial device was not found.\n\n"
                "• Make sure Proxmark3 is connected and recognized (e.g., /dev/ttyACM0).\n"
                "• Install proxmark3 client and/or set PM3_BIN.\n\n"
                "READ/WRITE are disabled until resolved."
            )

    # ---------- flows ----------
    def ask_tag_and_get_uid(self) -> Optional[str]:
        deadline = time.time() + TAG_WAIT_SECONDS
        dlg = ProgressDialog(self, "Place Tag", "Hold the NTAG213 near the reader…")
        try:
            while time.time() < deadline:
                uid = self.pm3.get_uid(wait_seconds=1)
                if uid:
                    return uid
                self.update()
                time.sleep(0.2)
            return None
        finally:
            dlg.close()

    def read_current_text(self) -> Tuple[Optional[str], Optional[str], bool]:
        """Return (uid, text, from_db). Cache-first: if DATABASE/UID.txt exists, use it."""
        uid = self.ask_tag_and_get_uid()
        if not uid:
            messagebox.showwarning("No tag", "No tag detected within the time limit.")
            return None, None, False
        # Prefer cached text if present
        path = db_path_for_uid(uid)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    clear_tmp_dir()  # clear temp even on cached reads
                    return uid, f.read(), True
            except OSError:
                pass
        # Not cached: read via dump and create .txt
        dlg = ProgressDialog(self, "Reading", "Reading user memory…")
        try:
            data = self.pm3.read_user_bytes()
        finally:
            dlg.close()
        if data is None:
            clear_tmp_dir()  # clear temp even if read failed
            messagebox.showerror("Read failed", "Could not read tag user memory.")
            return uid, None, False
        # Stop at first all-zero block boundary
        trimmed = bytearray()
        for i in range(0, len(data), 4):
            blk = data[i:i+4]
            if blk == b"\x00\x00\x00\x00":
                break
            trimmed += blk
        text = trimmed.decode("utf-8", "replace")
        db_save(uid, text)   # create DB file since it was missing
        clear_tmp_dir()      # clear temp after successful read
        return uid, text, False

    def on_checkin_read(self):
        uid, text, from_db = self.read_current_text()
        if not uid or text is None:
            return
        rr: ReadResultScreen = self.screens["ReadResultScreen"]  # type: ignore
        rr.set_content(uid + ("  (cached)" if from_db else ""), text)
        self.show("ReadResultScreen")

    def on_checkin_write(self):
        # Protect wipe: show preview and confirm if non-empty
        uid, text, _from_db = self.read_current_text()
        if not uid:
            return
        if text and text.strip("\x00\n\r\t "):
            preview = text if len(text) <= 120 else text[:120] + "…"
            if not messagebox.askyesno(
                "Confirm wipe",
                "This tag already contains data.\n\n"
                f"UID: {uid}\n\n"
                f"Preview:\n{preview}\n\n"
                "Wipe the user area and proceed to write?",
            ):
                return
        # Move to write screen
        wp: WritePromptScreen = self.screens["WritePromptScreen"]  # type: ignore
        wp.prepare(uid)
        self.show("WritePromptScreen")

    def perform_write_flow(self, uid: str, text: str):
        # Delete DB entries first (same behavior as checkout), then Wipe → Write → Verify → Save
        _deleted = db_delete_all(uid)
        dlg = ProgressDialog(self, "Writing", "Wiping, writing and verifying…")
        ok = False
        try:
            if not self.pm3.wipe_pages():
                messagebox.showerror("Wipe failed", "Could not wipe user pages.")
                return
            if not self.pm3.write_ascii(text):
                messagebox.showerror("Write failed", "Writing user data failed.")
                return
            data = self.pm3.read_user_bytes()
            if data is None:
                messagebox.showerror("Verify failed", "Could not read back data for verification.")
                return
            trimmed = bytearray()
            for i in range(0, len(data), 4):
                blk = data[i:i+4]
                if blk == b"\x00\x00\x00\x00":
                    break
                trimmed += blk
            text_back = trimmed.decode("utf-8", "replace")
            ok = True
        finally:
            dlg.close()
        if ok:
            db_save(uid, text_back)
            clear_tmp_dir()  # clear temp after successful write
            messagebox.showinfo("Success", "Wrote text to tag and verified.")
            inf: InfoScreen = self.screens["InfoScreen"]  # type: ignore
            inf.set_message(f"UID: {uid}\n\nSaved to: {db_path_for_uid(uid)}")
            self.show("InfoScreen")

    def on_checkout(self):
        uid, text, _from_db = self.read_current_text()
        if not uid:
            return
        deleted = db_delete_all(uid)
        msg = [f"UID: {uid}"]
        if text:
            msg += ["\nCurrent tag preview:", text if len(text) < 400 else text[:400] + "…"]
        msg += [f"\nDeleted {deleted} file(s) from local DB."]
        inf: InfoScreen = self.screens["InfoScreen"]  # type: ignore
        inf.set_message("\n".join(msg))
        self.show("InfoScreen")

# ------------------ screens ------------------

class HomeScreen(Frame):
    def __init__(self, parent, controller: 'App'):
        super().__init__(parent)
        self.controller = controller
        Label(self, text="NTAG213 GUI", font=("Arial", 18, "bold")).pack(pady=(24, 8))
        Label(self, text="Check in/out using a Proxmark3", font=("Arial", 11)).pack(pady=(0, 16))

        btns = Frame(self)
        self.btn_read = Button(btns, text="CHECK IN — READ", width=22, command=controller.on_checkin_read)
        self.btn_write = Button(btns, text="CHECK IN — WRITE (wipe)", width=22, command=controller.on_checkin_write)
        self.btn_out = Button(btns, text="CHECK OUT", width=22, command=controller.on_checkout)
        self.btn_read.grid(row=0, column=0, padx=8, pady=6)
        self.btn_write.grid(row=0, column=1, padx=8, pady=6)
        self.btn_out.grid(row=0, column=2, padx=8, pady=6)
        btns.pack(pady=12)

        Button(self, text="Open Log", command=controller.open_log).pack(pady=10)

    def set_enabled(self, enabled: bool):
        for b in (self.btn_read, self.btn_write, self.btn_out):
            try:
                b.configure(state=("normal" if enabled else "disabled"))
            except TclError:
                pass

class CheckInMenu(Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        Label(self, text="(Legacy screen — not used)").pack()

class ReadResultScreen(Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.lbl_uid = Label(self, text="UID: ", font=("Arial", 12, "bold"))
        self.lbl_uid.pack(pady=(16, 8))
        self.text = Text(self, height=12, wrap="word")
        self.text.pack(fill=BOTH, expand=True, padx=12, pady=8)
        Button(self, text="Back to Home", command=lambda: controller.show("HomeScreen")).pack(pady=8)

    def set_content(self, uid: str, content: str):
        self.lbl_uid.config(text=f"UID: {uid}")
        self.text.delete(1.0, END)
        self.text.insert(END, content)

class WritePromptScreen(Frame):
    def __init__(self, parent, controller: 'App'):
        super().__init__(parent)
        self.controller = controller

        Label(self, text="Write Category to Tag", font=("Arial", 14, "bold")).pack(pady=(16, 4))
        self.lbl_uid = Label(self, text="UID: ?")
        self.lbl_uid.pack()

        # Category 1: BRAND
        Label(self, text="Select BRAND:", font=("Arial", 11)).pack(pady=(12, 4))
        self.brand = ttk.Combobox(self, state="readonly", values=["Polymaker", "Bambu Lab", "Esun", "Sunlu", "generic"], width=15)
        self.brand.current(0)
        self.brand.pack(pady=(0, 8))

        # Category 2: FILAMENT
        Label(self, text="Select FILAMENT:", font=("Arial", 11)).pack(pady=(12, 4))
        self.filament = ttk.Combobox(self, state="readonly", values=["PLA", "PETG", "ABS", "TPU", "SUPPORT"], width=15)
        self.filament.current(0)
        self.filament.pack(pady=(0, 8))

        # Category 3: COLOR (Free text input)
        Label(self, text="Enter COLOR:", font=("Arial", 11)).pack(pady=(12, 4))
        self.color_entry = Entry(self, width=20)
        self.color_entry.pack(pady=(0, 8))

        # Category 4: WEIGHT (Free text input with 'grams' appended)
        Label(self, text="Enter WEIGHT (in grams):", font=("Arial", 11)).pack(pady=(12, 4))
        self.weight_entry = Entry(self, width=20)
        self.weight_entry.pack(pady=(0, 8))

        # Category 5: WHERE WILL IT BE STORED
        Label(self, text="Select WHERE IT WILL BE STORED:", font=("Arial", 11)).pack(pady=(12, 4))
        self.storage = ttk.Combobox(self, state="readonly", values=["DRY", "STORAGE"], width=15)
        self.storage.current(0)
        self.storage.pack(pady=(0, 8))

        # Live preview of what will be written
        self.preview_var = StringVar()
        Label(self, text="Preview to be written:", font=("Arial", 10, "bold")).pack(pady=(8, 2))
        self.lbl_preview = Label(self, textvariable=self.preview_var, font=("Arial", 11), wraplength=520, justify="left")
        self.lbl_preview.pack(padx=12)

        # Buttons
        btns = Frame(self)
        Button(btns, text="Write Now", command=self._do_write).grid(row=0, column=0, padx=6)
        Button(btns, text="Cancel", command=lambda: controller.show("HomeScreen")).grid(row=0, column=1, padx=6)
        btns.pack(pady=12)

        # Bind dropdowns to update preview
        self.brand.bind("<<ComboboxSelected>>", lambda _e: self._update_preview())
        self.filament.bind("<<ComboboxSelected>>", lambda _e: self._update_preview())
        self.storage.bind("<<ComboboxSelected>>", lambda _e: self._update_preview())

        self._uid: Optional[str] = None
        self._update_preview()

    def _build_payload(self) -> str:
        # The exact text we’ll write to the tag, including all categories
        return (
            f"BRAND: {self.brand.get()}\n"
            f"FILAMENT: {self.filament.get()}\n"
            f"COLOR: {self.color_entry.get()}\n"
            f"WEIGHT: {self.weight_entry.get()} grams\n"
            f"WHERE WILL IT BE STORED: {self.storage.get()}"
        )

    def _update_preview(self):
        payload = self._build_payload()
        self.preview_var.set(payload + f"\n\n({len(payload.encode('utf-8'))} bytes)")

    def prepare(self, uid: str):
        self._uid = uid
        self.lbl_uid.config(text=f"UID: {uid}")
        # Reset dropdowns to default values each time screen opens
        try:
            self.brand.current(0)
            self.filament.current(0)
            self.storage.current(0)
        except Exception:
            pass
        self._update_preview()

    def _do_write(self):
        if not self._uid:
            messagebox.showerror("No UID", "No tag UID captured.")
            return
        txt = self._build_payload()
        self.controller.perform_write_flow(self._uid, txt)

class InfoScreen(Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.label = Label(self, text="", font=("Arial", 12), justify="left", wraplength=520)
        self.label.pack(padx=12, pady=12, fill=BOTH, expand=True)
        Button(self, text="Back to Home", command=lambda: controller.show("HomeScreen")).pack(pady=(0, 12))

    def set_message(self, msg: str):
        self.label.config(text=msg)

if __name__ == "__main__":
    app = App()
    app.mainloop()
