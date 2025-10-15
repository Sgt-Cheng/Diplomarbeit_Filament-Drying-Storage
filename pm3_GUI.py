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

def db_save(uid: str, content: str, storage_location: str):
    # Determine the subfolder (DRY or STORAGE)
    if storage_location == "DRY":
        subfolder = "DRY"
    elif storage_location == "STORAGE":
        subfolder = "STORAGE"
    else:
        # Default to DRY if something goes wrong
        subfolder = "DRY"

    # Construct the file path in the correct subfolder
    db_path = os.path.join("DATABASE", subfolder, f"{uid}.txt")

    # Make sure the subfolder exists (create it if not)
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    # Save the content to the correct file
    with open(db_path, "w") as f:
        f.write(content)

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

        # Menu setup and other initializations...

        # Screens setup
        self.container = Frame(self)
        self.container.pack(fill=BOTH, expand=True)
        self.screens = {}
        for cls in (HomeScreen, ReadResultScreen, WritePromptScreen, InfoScreen):  # Ensure ReadResultScreen is defined
            scr = cls(self.container, self)
            self.screens[cls.__name__] = scr
            scr.grid(row=0, column=0, sticky="nsew")
        self.show("HomeScreen")

        self._update_status()
        self._apply_pm3_availability()

    # ---------- Method to log messages ----------
    def _log(self, message: str):
        print(message)  # Simply print messages for now
        if self._logwin and self._logwin.winfo_exists():
            self._logwin.append(message)

    # ---------- Method for handling check-in read ----------
    def on_checkin_read(self):
        uid, text, from_db = self.read_current_text()
        if not uid or text is None:
            return
        rr: ReadResultScreen = self.screens["ReadResultScreen"]  # type: ignore
        rr.set_content(uid + ("  (cached)" if from_db else ""), text)
        self.show("ReadResultScreen")

    # ---------- Method for handling check-in write ----------
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

    # ---------- Method for handling checkout ----------
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

if __name__ == "__main__":
    app = App()
    app.mainloop()
