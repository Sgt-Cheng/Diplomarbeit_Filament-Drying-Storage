#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import glob
import time
import shutil
import subprocess
from tkinter import (
    Tk, Toplevel, Frame, Button, Label, Text, StringVar,
    END, BOTH, LEFT, RIGHT, BOTTOM, X, Y, messagebox, Menu, Scrollbar, TclError
)

# ========== CONFIG ==========

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

PM3_BIN_CANDIDATES = [
    os.environ.get("PM3_BIN"),
    os.path.join(SCRIPT_DIR, "..", "pm3"),
    os.path.join(SCRIPT_DIR, "..", "client", "proxmark3"),
    "pm3",
]

# NTAG213 user memory pages
START_PAGE = 4
END_PAGE   = 39   # 36 pages * 4 bytes = 144 bytes

TAG_WAIT_SECONDS   = 10
TAG_POLL_INTERVAL  = 0.7

DATABASE_DIR = os.path.join(SCRIPT_DIR, "DATABASE")
os.makedirs(DATABASE_DIR, exist_ok=True)

# ========== Helpers ==========

def _which(path):
    return path if path and (os.path.isfile(path) or shutil.which(path)) else None

def find_pm3_bin():
    for cand in PM3_BIN_CANDIDATES:
        p = _which(cand)
        if p:
            return p
    return None

def detect_pm3_serial():
    for path in sorted(glob.glob("/dev/ttyACM*")):
        return path
    for path in sorted(glob.glob("/dev/ttyUSB*")):
        return path
    return None

UID_RE = re.compile(r"UID:\s*([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})+)")

NOTAG_PATTERNS = (
    "no tag found", "no 14443-a tag found", "no tag detected",
    "can't select tag", "error: no tag", "tag not found"
)

# ========== PM3 interface + logging ==========

class PM3:
    def __init__(self, logger):
        self.logger = logger
        self.pm3_bin = find_pm3_bin()
        self.serial = detect_pm3_serial()

    def argv(self):
        if not self.pm3_bin:
            return None
        argv = [self.pm3_bin]
        if self.serial:
            argv += ["-d", self.serial]
        return argv

    def run(self, commands, timeout=60, title=None):
        """
        Run pm3 commands (commands is a list of strings). Returns (rc, out, err) as strings.
        """
        argv = self.argv()
        if argv is None:
            err = ("Proxmark client not found. Set PM3_BIN or ensure one of:\n"
                   "  ../pm3\n  ../client/proxmark3\n  pm3 in PATH\n"
                   f"Script dir: {SCRIPT_DIR}")
            self.logger(title or "pm3", "ERROR starting pm3", err)
            return 1, "", err

        stdin = "\n".join(commands) + "\nquit\n"
        self.logger(title or "pm3", f"$ {' '.join(argv)}", "\n".join(commands))
        try:
            proc = subprocess.run(
                argv, input=stdin, capture_output=True, timeout=timeout,
                text=True, encoding="utf-8", errors="replace"
            )
            out, err = proc.stdout or "", proc.stderr or ""
            self.logger(title or "pm3", "stdout:", out.strip())
            if err.strip():
                self.logger(title or "pm3", "stderr:", err.strip())
            return proc.returncode, out, err
        except subprocess.TimeoutExpired as e:
            self.logger(title or "pm3", "TIMEOUT", str(e))
            return 2, (e.stdout or ""), f"Timeout: {e}"
        except Exception as e:
            self.logger(title or "pm3", "EXCEPTION", repr(e))
            return 3, "", f"Error launching pm3: {e}"

    # Combined probe to avoid back-to-back sessions
    def probe_uid_single_session(self):
        rc, out, err = self.run(["hf 14a reader", "hf search"], timeout=20, title="probe")
        uid = None
        if out:
            m = UID_RE.search(out)
            if m:
                uid = m.group(1).replace(" ", "").upper()
        return uid, out, err

    def get_uid(self, wait_seconds=TAG_WAIT_SECONDS, poll_interval=TAG_POLL_INTERVAL):
        last_out, last_err = "", ""
        deadline = time.time() + wait_seconds
        while time.time() < deadline:
            uid, out, err = self.probe_uid_single_session()
            last_out, last_err = out, err
            if uid:
                return uid, out, err
            lower = (out or "").lower()
            if any(p in lower for p in NOTAG_PATTERNS):
                time.sleep(poll_interval)
                continue
            time.sleep(poll_interval)
        return None, last_out, last_err

    def mfu_info(self):
        return self.run(["hf mfu info"], timeout=20, title="mfu info")

    # Write: use -b <block> -d <hexdata>
    def mfu_wipe_pages(self, start_page=START_PAGE, end_page=END_PAGE):
        cmds = [f"hf mfu wrbl -b {p} -d 00000000" for p in range(start_page, end_page + 1)]
        return self.run(cmds, timeout=200, title="mfu wipe")

    def mfu_write_ascii(self, text, start_page=START_PAGE, end_page=END_PAGE):
        total = (end_page - start_page + 1) * 4
        data = (text or "").encode("utf-8")
        if len(data) > total:
            data = data[:total]
        if len(data) % 4 != 0:
            data += b"\x00" * (4 - (len(data) % 4))
        cmds = []
        page = start_page
        for i in range(0, len(data), 4):
            word = data[i : i + 4].hex()
            cmds.append(f"hf mfu wrbl -b {page} -d {word}")
            page += 1
            if page > end_page:
                break
        return self.run(cmds, timeout=200, title="mfu write")

    def mfu_read_block(self, block):
        return self.run([f"hf mfu rdbl -b {block}"], timeout=15, title=f"mfu rdbl {block}")

# ========== Parse + DB ==========

def parse_ascii_from_blocks(pm3, start_page=START_PAGE, end_page=END_PAGE):
    """Read block-by-block and build ASCII until a null block or first zero byte."""
    output_bytes = bytearray()
    for p in range(start_page, end_page + 1):
        rc, out, err = pm3.mfu_read_block(p)
        if rc != 0:
            break
        # parse hex bytes in the output lines
        hex_bytes = re.findall(r"\b[0-9A-Fa-f]{2}\b", out)
        if len(hex_bytes) < 4:
            break
        block_data = bytes(int(b, 16) for b in hex_bytes[:4])
        # if the entire block is zero, stop
        if block_data == b"\x00\x00\x00\x00":
            break
        output_bytes.extend(block_data)
    try:
        return output_bytes.decode("utf-8", errors="replace")
    except:
        return output_bytes.decode("latin-1", errors="replace")

def db_path_for_uid(uid):
    return os.path.join(DATABASE_DIR, f"{uid}.txt")

def db_save(uid, text):
    with open(db_path_for_uid(uid), "w", encoding="utf-8") as f:
        f.write(text or "")

def db_delete_all(uid):
    deleted = failed = 0
    for name in os.listdir(DATABASE_DIR):
        if uid in name:
            path = os.path.join(DATABASE_DIR, name)
            try:
                os.remove(path)
                deleted += 1
            except:
                failed += 1
    return deleted, failed

# ========== GUI ==========

class LogWindow(Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Log")
        self.geometry("720x420")
        self.text = Text(self, wrap="word")
        self.scroll = Scrollbar(self, command=self.text.yview)
        self.text.configure(yscrollcommand=self.scroll.set)
        self.text.pack(side=LEFT, fill=BOTH, expand=True)
        self.scroll.pack(side=RIGHT, fill=Y)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _on_close(self):
        self.withdraw()

    def append(self, title, *lines):
        ts = time.strftime("%H:%M:%S")
        try:
            self.text.insert(END, f"[{ts}] [{title}] ")
            self.text.insert(END, "\n".join(lines) + "\n\n")
            self.text.see(END)
        except TclError:
            pass

class App(Tk):
    def __init__(self):
        super().__init__()
        self.title("NFC Check-In / Check-Out (NTAG213)")
        self.geometry("560x380")
        self.resizable(False, False)

        menubar = Menu(self)
        viewmenu = Menu(menubar, tearoff=0)
        viewmenu.add_command(label="Log", command=self.show_log)
        menubar.add_cascade(label="View", menu=viewmenu)
        self.config(menu=menubar)

        self.log_win = None
        self.pm3 = PM3(self.log)

        self.container = Frame(self)
        self.container.pack(fill=BOTH, expand=True)

        self.frames = {}
        for F in (HomeScreen, CheckInMenu, ReadResultScreen, WritePromptScreen, InfoScreen):
            frame = F(parent=self.container, controller=self)
            self.frames[F.__name__] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        bottom = Frame(self)
        bottom.pack(side=BOTTOM, fill=X)
        Button(bottom, text="Cancel", height=2, command=self.show_home).pack(side=RIGHT, padx=8, pady=6)

        self.status_var = StringVar()
        Label(bottom, textvariable=self.status_var, anchor="w").pack(side=LEFT, padx=8)
        self.update_status()

        self.show_home()

    def show_log(self):
        if self.log_win and self.log_win.winfo_exists():
            self.log_win.deiconify()
            return
        self.log_win = LogWindow(self)

    def log(self, title, *lines):
        if not self.log_win or not self.log_win.winfo_exists():
            self.show_log()
        try:
            self.log_win.append(title, *lines)
        except TclError:
            self.show_log()
            try:
                self.log_win.append(title, *lines)
            except TclError:
                pass

    def update_status(self):
        pm3p = self.pm3.pm3_bin or "<not found>"
        dev = self.pm3.serial or "<no serial>"
        self.status_var.set(f"pm3: {pm3p}   dev: {dev}")

    def show_frame(self, name):
        self.frames[name].tkraise()
    def show_home(self):
        self.show_frame("HomeScreen")

    # --- Actions ---

    def action_check_in_read(self):
        messagebox.showinfo("Place Tag", "Place a tag on the reader, then OK.")
        uid, out, err = self.pm3.get_uid()
        if not uid:
            messagebox.showerror("No Tag", "No tag detected. Check logs.")
            return

        ascii_text = parse_ascii_from_blocks(self.pm3, START_PAGE, END_PAGE)
        db_save(uid, ascii_text)

        screen = self.frames["ReadResultScreen"]
        screen.set_content(uid, ascii_text)
        self.show_frame("ReadResultScreen")

    def action_check_in_write(self):
        messagebox.showinfo("Place Tag", "Place tag to WRITE (will wipe) then OK.")
        uid, out, err = self.pm3.get_uid()
        if not uid:
            messagebox.showerror("No Tag", "No tag detected.")
            return

        rc, o, e = self.pm3.mfu_info()
        if o.strip():
            self.log("mfu info (pre-write)", o.strip())

        screen = self.frames["WritePromptScreen"]
        screen.set_uid(uid)
        screen.reset()
        self.show_frame("WritePromptScreen")

    def perform_write_with_wipe(self, uid, text_to_write):
        rc, o, e = self.pm3.mfu_wipe_pages()
        if rc != 0:
            messagebox.showerror("Wipe Error", "Could not wipe. Check log.")
            return

        rc, o, e = self.pm3.mfu_write_ascii(text_to_write)
        if rc != 0:
            messagebox.showerror("Write Error", "Write failed. Check log.")
            return

        ascii_text = parse_ascii_from_blocks(self.pm3, START_PAGE, END_PAGE)
        db_save(uid, ascii_text)

        info = self.frames["InfoScreen"]
        info.set_message(f"Write OK.\nUID: {uid}\nSaved to DATABASE/{uid}.txt")
        self.show_frame("InfoScreen")

    def action_check_out(self):
        messagebox.showinfo("Place Tag", "Place tag to CHECK OUT then OK.")
        uid, out, err = self.pm3.get_uid()
        if not uid:
            messagebox.showerror("No Tag", "No tag detected.")
            return

        # Read ASCII from blocks (temporarily)
        ascii_text = parse_ascii_from_blocks(self.pm3, START_PAGE, END_PAGE)

        deleted, failed = db_delete_all(uid)
        if deleted > 0 and failed == 0:
            msg = f"CHECK OUT successful: deleted {deleted} files for UID {uid}."
        elif deleted > 0:
            msg = f"CHECK OUT partial: deleted {deleted}, but {failed} failed."
        else:
            msg = f"No files found for UID {uid}."

        if ascii_text:
            msg += "\n\nRead text preview:\n" + ascii_text[:200]

        info = self.frames["InfoScreen"]
        info.set_message(msg)
        self.show_frame("InfoScreen")

class HomeScreen(Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        Label(self, text="NFC Station (NTAG213)", font=("Arial", 18, "bold")).pack(pady=16)
        row = Frame(self); row.pack(pady=12)
        Button(row, text="CHECK IN", width=16, height=3,
               command=lambda: controller.show_frame("CheckInMenu")).pack(side=LEFT, padx=10)
        Button(row, text="CHECK OUT", width=16, height=3,
               command=controller.action_check_out).pack(side=RIGHT, padx=10)

class CheckInMenu(Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        Label(self, text="CHECK IN", font=("Arial", 16, "bold")).pack(pady=14)
        Button(self, text="READ", width=18, height=3,
               command=controller.action_check_in_read).pack(pady=8)
        Button(self, text="WRITE (wipe first)", width=18, height=3,
               command=controller.action_check_in_write).pack(pady=8)

class ReadResultScreen(Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.uid_var = StringVar(value="")
        Label(self, text="READ RESULT", font=("Arial", 16, "bold")).pack(pady=10)
        Label(self, textvariable=self.uid_var, font=("Arial", 12)).pack(pady=4)
        self.textbox = Text(self, height=10, width=64, wrap="word")
        self.textbox.pack(padx=10, pady=10)

    def set_content(self, uid, text):
        self.uid_var.set(f"UID: {uid}")
        self.textbox.delete(1.0, END)
        self.textbox.insert(END, text if text else "(no ASCII text)")

class WritePromptScreen(Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.uid = None
        Label(self, text="WRITE TEXT TO TAG", font=("Arial", 16, "bold")).pack(pady=10)
        Label(self, text="(Tag will be wiped first)", font=("Arial", 10)).pack(pady=2)
        self.textbox = Text(self, height=8, width=64, wrap="word")
        self.textbox.pack(padx=10, pady=10)
        Button(self, text="Write Now", width=14, height=2,
               command=self._do_write).pack(pady=6)

    def set_uid(self, uid):
        self.uid = uid

    def reset(self):
        self.textbox.delete(1.0, END)

    def _do_write(self):
        text = self.textbox.get(1.0, END).strip()
        if not text:
            if not messagebox.askyesno("Empty Text", "No text entered — write zeros?"):
                return
        if not self.uid:
            messagebox.showerror("Internal", "Missing UID context. Try again.")
            return
        self.controller.perform_write_with_wipe(self.uid, text)

class InfoScreen(Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.label = Label(self, text="", font=("Arial", 12), justify="left", wraplength=520)
        self.label.pack(padx=12, pady=12, fill=BOTH, expand=True)

    def set_message(self, msg):
        self.label.config(text=msg)


if __name__ == "__main__":
    app = App()
    app.mainloop()
