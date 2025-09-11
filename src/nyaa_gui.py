#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NYAA GUI — Nested Yet Another Archiver (ttk, compact, src/assets-aware)

Dependencies:
    pip install zstandard cryptography Pillow

Build (PowerShell, onedir):
    pyinstaller --windowed --onedir --noconfirm ^
      --icon "assets/badge.ico" ^
      --add-data "assets/banner.png:assets" ^
      --add-data "assets/badge.ico:assets" ^
      --collect-all zstandard --collect-all cryptography --collect-all Pillow ^
      src/nyaa_gui.py
"""

import os
import sys
import io
import contextlib
import threading
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk

# ---- paths (src / assets) ----
SRC_DIR = Path(__file__).resolve().parent           # .../repo/src
ROOT_DIR = SRC_DIR.parent                           # .../repo
ASSETS_DIR = ROOT_DIR / "assets"

# allow `import nyaa` from src/
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

try:
    import nyaa  # from src/nyaa.py
except Exception:
    nyaa = None


def asset_path(name: str) -> str:
    """
    Returns path to asset file (banner, icon) — compatible with PyInstaller
    In bundled mode, assets are in ./assets/ inside the build
    """
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, "assets", name)
    return str(ASSETS_DIR / name)


class NyaaGUI(tk.Tk):
    def __init__(self):
        super().__init__()

        # Minimum size = starting size
        MIN_W, MIN_H = 880, 600
        self.title("NYAA — Nested Yet Another Archiver")
        self.minsize(MIN_W, MIN_H)
        self.geometry(f"{MIN_W}x{MIN_H}")
        try:
            self.iconbitmap(asset_path("badge.ico"))
        except Exception:
            pass

        # Soft theme colors
        base_bg = "#f6efe9"
        pane_bg = "#faf4ee"
        self.configure(bg=base_bg)

        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(".", background=base_bg)
        style.configure("TFrame", background=base_bg)
        style.configure("TLabelFrame", background=pane_bg, relief="flat", borderwidth=1)
        style.configure("TSeparator", background="#e3d9d0")
        style.configure("TButton", padding=6)
        style.map("TButton", background=[("active", "#f2d9cc")])

        # ===== Top banner + log panel =====
        top = ttk.Frame(self)
        top.pack(fill=tk.X, padx=8, pady=(8, 0))

        # Load and scale banner
        self._banner_imgtk = None
        try:
            banner = Image.open(asset_path("banner.png")).convert("RGBA")
            banner.thumbnail((300, 100), Image.LANCZOS)
            self._banner_imgtk = ImageTk.PhotoImage(banner)
            ttk.Label(top, image=self._banner_imgtk).pack(side=tk.LEFT, padx=(0, 10))
        except Exception:
            pass

        # Log: white, read‑only, 6 rows
        log_frame = ttk.Frame(top)
        log_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

        yscroll = ttk.Scrollbar(log_frame, orient="vertical")
        self.txt = tk.Text(
            log_frame, height=6, bg="white", font=("Consolas", 9),
            yscrollcommand=yscroll.set
        )
        yscroll.config(command=self.txt.yview)
        self.txt.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        log_frame.columnconfigure(0, weight=1)

        # Disable typing except for Ctrl+C
        def _log_key_block(e):
            if (e.state & 0x4) and e.keysym.lower() == "c":
                return None
            return "break"
        self.txt.bind("<Key>", _log_key_block)
        self.txt.configure(state="disabled")

        self.append_log("Ready. Add files/folders, then click «Create archive».")
        if nyaa is None:
            self.append_log("⚠ Unable to import nyaa.py. Place nyaa.py in src/.")

        ttk.Separator(self, orient="horizontal").pack(fill=tk.X, padx=8, pady=(8, 6))

        # ===== Archive actions (in 2 groups) =====
        actions = ttk.LabelFrame(self, text="Archive actions")
        actions.pack(fill=tk.X, padx=8, pady=(0, 8))
        actions.columnconfigure(0, weight=1)
        actions.columnconfigure(2, weight=0)
        actions.columnconfigure(4, weight=1)

        left = ttk.Frame(actions)
        left.grid(row=0, column=1, sticky="w", padx=4, pady=4)
        ttk.Button(left, text="Add files", command=self.add_files).pack(side=tk.LEFT, padx=3)
        ttk.Button(left, text="Add folder", command=self.add_dir).pack(side=tk.LEFT, padx=3)
        ttk.Button(left, text="Clear", command=self.clear_list).pack(side=tk.LEFT, padx=3)

        ttk.Separator(actions, orient="vertical").grid(row=0, column=2, sticky="ns", padx=6, pady=2)

        right = ttk.Frame(actions)
        right.grid(row=0, column=3, sticky="e", padx=4, pady=4)
        ttk.Button(right, text="Create archive", command=self.on_pack).pack(side=tk.LEFT, padx=3)
        ttk.Button(right, text="List", command=self.on_list).pack(side=tk.LEFT, padx=3)
        ttk.Button(right, text="Extract", command=self.on_unpack).pack(side=tk.LEFT, padx=3)

        # ===== Queue: compact 6‑row Listbox =====
        lstf = ttk.LabelFrame(self, text="Queue")
        lstf.pack(fill=tk.X, padx=8, pady=6)
        self.listbox = tk.Listbox(lstf, selectmode=tk.EXTENDED, height=6)
        self.listbox.pack(fill=tk.X, expand=False, padx=6, pady=6)
        self.selected_paths: list[str] = []

        ttk.Separator(self, orient="horizontal").pack(fill=tk.X, padx=8, pady=(6, 6))

        # ===== Options section =====
        opts = ttk.LabelFrame(self, text="Options")
        opts.pack(fill=tk.X, padx=8, pady=(0, 8))

        self.out_archive_var = tk.StringVar(value="archive.nyaa")
        self.extract_dir_var = tk.StringVar(value=str((ROOT_DIR / "nyaa_out").resolve()))
        self.encrypt_var = tk.BooleanVar(value=False)
        self.password_var = tk.StringVar(value="")
        self.level_var = tk.IntVar(value=10)

        ttk.Label(opts, text="Output archive:").grid(row=0, column=0, sticky="w", padx=6, pady=6)
        ttk.Entry(opts, textvariable=self.out_archive_var, width=44).grid(row=0, column=1, sticky="we", padx=6, pady=6)
        ttk.Button(opts, text="Browse…", command=self.choose_archive_name).grid(row=0, column=2, padx=6, pady=6)

        ttk.Label(opts, text="Compression level (zstd 1..22):").grid(row=1, column=0, sticky="w", padx=6, pady=6)
        s = ttk.Scale(opts, from_=1, to=22, orient=tk.HORIZONTAL, variable=self.level_var)
        s.grid(row=1, column=1, sticky="we", padx=6, pady=6)
        self.lbl_level = ttk.Label(opts, text=str(self.level_var.get()))
        self.lbl_level.grid(row=1, column=2, sticky="w", padx=6, pady=6)
        s.bind("<B1-Motion>", lambda e: self.lbl_level.config(text=str(int(self.level_var.get()))))
        s.bind("<ButtonRelease-1>", lambda e: self.lbl_level.config(text=str(int(self.level_var.get()))))

        ttk.Checkbutton(
            opts, text="Encryption (AES‑256‑GCM)",
            variable=self.encrypt_var, command=self.toggle_encrypt
        ).grid(row=2, column=0, sticky="w", padx=6, pady=6)
        self.ent_pwd = ttk.Entry(opts, textvariable=self.password_var, show="•", state="disabled", width=30)
        self.ent_pwd.grid(row=2, column=1, sticky="w", padx=6, pady=6)

        ttk.Label(opts, text="Extract to:").grid(row=3, column=0, sticky="w", padx=6, pady=6)
        ttk.Entry(opts, textvariable=self.extract_dir_var, width=44).grid(row=3, column=1, sticky="we", padx=6, pady=6)
        ttk.Button(opts, text="Browse…", command=self.choose_extract_dir).grid(row=3, column=2, padx=6, pady=6)

        opts.columnconfigure(1, weight=1)

    # ---------- Utility ----------
    def append_log(self, msg: str):
        self.txt.configure(state="normal")
        self.txt.insert(tk.END, msg + "\n")
        self.txt.see(tk.END)
        self.txt.configure(state="disabled")

    def choose_archive_name(self):
        p = filedialog.asksaveasfilename(
            title="Output archive",
            defaultextension=".nyaa",
            filetypes=[("NYAA archive", "*.nyaa")],
            initialfile=self.out_archive_var.get(),
        )
        if p:
            self.out_archive_var.set(p)

    def choose_extract_dir(self):
        p = filedialog.askdirectory(title="Extract to", initialdir=self.extract_dir_var.get())
        if p:
            self.extract_dir_var.set(p)

    def toggle_encrypt(self):
        if self.encrypt_var.get():
            self.ent_pwd.configure(state="normal")
        else:
            self.ent_pwd.configure(state="disabled")
            self.password_var.set("")

    def add_files(self):
        paths = filedialog.askopenfilenames(title="Choose files")
        for p in paths:
            if p and p not in self.selected_paths:
                self.selected_paths.append(p)
                self.listbox.insert(tk.END, p)

    def add_dir(self):
        p = filedialog.askdirectory(title="Choose folder")
        if p:
            self.selected_paths.append(p)
            self.listbox.insert(tk.END, p)

    def clear_list(self):
        self.selected_paths.clear()
        self.listbox.delete(0, tk.END)

    # ---------- Threaded Actions ----------
    def run_thread(self, target, *args, **kwargs):
        t = threading.Thread(target=self._run_catch, args=(target,) + args, kwargs=kwargs, daemon=True)
        t.start()

    def _run_catch(self, target, *args, **kwargs):
        try:
            target(*args, **kwargs)
        except Exception as e:
            self.append_log(f"❌ Error: {e}")
            messagebox.showerror("NYAA GUI", f"Error: {e}")

    def on_pack(self):
        if nyaa is None:
            messagebox.showerror("NYAA GUI", "nyaa.py not found.")
            return
        if not self.selected_paths:
            messagebox.showwarning("NYAA GUI", "Select at least one file or folder.")
            return
        out = Path(self.out_archive_var.get())
        level = int(self.level_var.get())
        password = self.password_var.get() if self.encrypt_var.get() else None
        self.append_log(f"→ Creating archive: {out}")
        self.run_thread(self._do_pack, out, self.selected_paths, level, password)

    def _do_pack(self, out, paths, level, password):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            nyaa.write_archive(Path(out), paths, level=level, password=password)
        captured = buf.getvalue().strip()
        if not captured:
            return
        for line in captured.splitlines():
            s = line.strip()
            # if legacy core prints "Joke:", keep only the text
            if s.lower().startswith("joke:"):
                s = s.split(":", 1)[1].strip()
                if not s:
                    continue
            self.append_log(s)

    def on_list(self):
        if nyaa is None:
            messagebox.showerror("NYAA GUI", "nyaa.py not found.")
            return
        p = filedialog.askopenfilename(title="Choose .nyaa archive", filetypes=[("NYAA archive", "*.nyaa")])
        if not p:
            return
        self.append_log(f"→ Listing: {p}")
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                nyaa.list_archive(Path(p), password=None)
            out = buf.getvalue().strip()
            if out:
                self.append_log(out)
        except Exception as e:
            self.append_log(f"❌ Error: {e}")

    def on_unpack(self):
        if nyaa is None:
            messagebox.showerror("NYAA GUI", "nyaa.py not found.")
            return
        p = filedialog.askopenfilename(title="Choose .nyaa archive", filetypes=[("NYAA archive", "*.nyaa")])
        if not p:
            return
        outdir = Path(self.extract_dir_var.get())
        password = self.password_var.get() if self.encrypt_var.get() else None
        self.append_log(f"→ Extract: {p} → {outdir}")
        self.run_thread(self._do_unpack, p, outdir, password)

    def _do_unpack(self, archive, outdir, password):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            nyaa.extract_archive(Path(archive), Path(outdir), password=password)
        captured = buf.getvalue().strip()
        if captured:
            for line in captured.splitlines():
                self.append_log(line)
        self.append_log("✔ Extraction finished.")


if __name__ == "__main__":
    app = NyaaGUI()
    # Rounded corners for Windows 11
    try:
        import ctypes
        DWMWA_WINDOW_CORNER_PREFERENCE = 33
        DWMWCP_ROUND = 2
        hwnd = ctypes.windll.user32.GetParent(app.winfo_id())
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd,
            ctypes.c_int(DWMWA_WINDOW_CORNER_PREFERENCE),
            ctypes.byref(ctypes.c_int(DWMWCP_ROUND)),
            ctypes.sizeof(ctypes.c_int),
        )
    except Exception:
        pass
    app.mainloop()