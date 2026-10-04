#!/usr/bin/env python3
"""Modern simplified GUI for SSL certificates (thin layer over cert_core)."""
from __future__ import annotations

import os
import sys
import traceback
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    from cert_core import (
        CaRequest,
        KeySpec,
        LeafRequest,
        OutputSpec,
        SubjectInfo,
        issue_intermediate_ca,
        issue_self_signed_ca,
        issue_signed_leaf,
        issue_standalone,
        load_cert,
        parse_san_list,
    )
    from cryptography import x509
except ImportError as e:
    raise SystemExit(
        "Missing dependency: %s\nRun: pip install cryptography" % e
    )

DEFAULT_OUT_DIR = os.path.join(os.getcwd(), "certs")

MODES = ("Root CA", "Server cert", "Standalone", "Intermediate")

MODE_HINT = {
    "Root CA": "Create a self-signed Root CA. Use it later to sign servers.",
    "Server cert": "Issue a server certificate signed by your CA.",
    "Standalone": "Quick self-signed certificate, no CA needed.",
    "Intermediate": "Sub-CA signed by the Root.",
}

VALIDITY_PRESETS = {
    "1 year - 825 days (browser limit)": 825,
    "2 years - 730 days": 730,
    "5 years - 1825 days": 1825,
    "10 years - 3650 days (CA)": 3650,
}

KEY_PRESETS = {
    "RSA 2048 (recommended)": ("rsa", 2048, "SECP256R1"),
    "RSA 4096 (stronger)": ("rsa", 4096, "SECP256R1"),
    "EC P-256 (fast, modern)": ("ec", 2048, "SECP256R1"),
    "EC P-384 (strong, modern)": ("ec", 2048, "SECP384R1"),
}

MODE_DEFAULTS = {
    "Root CA": {"cn": "My Root CA", "filename": "ca", "validity": "10 years - 3650 days (CA)"},
    "Server cert": {"cn": "example.com", "filename": "server", "validity": "1 year - 825 days (browser limit)"},
    "Standalone": {"cn": "localhost", "filename": "localhost", "validity": "1 year - 825 days (browser limit)"},
    "Intermediate": {"cn": "My Intermediate CA", "filename": "intermediate", "validity": "5 years - 1825 days"},
}


def open_folder(path: str) -> None:
    try:
        if sys.platform.startswith("win"):
            os.startfile(path)  # noqa
        elif sys.platform == "darwin":
            os.system('open "%s"' % path)
        else:
            os.system('xdg-open "%s"' % path)
    except Exception as e:
        messagebox.showwarning("Warning", "Could not open folder:\n%s" % e)


def apply_modern_style(root: tk.Tk) -> ttk.Style:
    style = ttk.Style()
    for theme in ("clam", "vista", "xpnative", "default"):
        try:
            style.theme_use(theme)
            break
        except tk.TclError:
            continue
    bg = "#F1F5F9"
    card_bg = "#FFFFFF"
    accent = "#2563EB"
    accent_active = "#1D4ED8"
    try:
        root.configure(bg=bg)
        style.configure("TFrame", background=bg)
        style.configure("Card.TFrame", background=card_bg)
        style.configure("Title.TLabel", background=bg, font=("Segoe UI", 16, "bold"))
        style.configure("Subtitle.TLabel", background=bg, foreground="#64748B", font=("Segoe UI", 10))
        style.configure("CardTitle.TLabel", background=card_bg, font=("Segoe UI", 10, "bold"))
        style.configure("Hint.TLabel", background=bg, foreground="#475569", font=("Segoe UI", 9))
        style.configure("Status.TLabel", background=bg, foreground="#334155", font=("Segoe UI", 9))
        style.configure("Result.TLabel", background=bg, foreground="#15803D", font=("Segoe UI", 9))
        style.configure("TLabel", background=bg)
        style.configure("TLabelframe", background=card_bg, borderwidth=0)
        style.configure("Card.TLabelframe", background=card_bg, borderwidth=1, relief="flat")
        style.configure("Card.TLabelframe.Label", background=card_bg, font=("Segoe UI", 10, "bold"))
        style.configure("Accent.TButton", background=accent, foreground="white",
                        font=("Segoe UI", 11, "bold"), padding=(12, 10), borderwidth=0)
        style.map("Accent.TButton", background=[("active", accent_active), ("disabled", "#93C5FD")])
        style.configure("Ghost.TButton", padding=(8, 6))
        style.configure("Mode.TRadiobutton", background=bg, font=("Segoe UI", 10))
    except Exception:
        pass
    return style


class CertApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("SSL Certificate Generator")
        root.geometry("640x820")
        root.minsize(560, 680)
        apply_modern_style(root)

        self.mode = tk.StringVar(value="Server cert")
        self.advanced_open = tk.BooleanVar(value=False)
        self.status = tk.StringVar(value="Ready.")
        self.result_path = tk.StringVar(value="")

        # Header
        header = ttk.Frame(root, padding=(16, 14, 16, 0))
        header.pack(fill="x")
        ttk.Label(header, text="SSL Certificate Generator", style="Title.TLabel").pack(anchor="w")
        ttk.Label(header, text="Self-signed CA and leaf certificates in one click",
                  style="Subtitle.TLabel").pack(anchor="w", pady=(0, 8))

        # Mode selector card
        mode_card = ttk.LabelFrame(root, text=" 1 - What do you want to create? ", padding=10)
        mode_card.pack(fill="x", padx=16, pady=6)
        mode_row = ttk.Frame(mode_card)
        mode_row.pack(fill="x")
        for m in MODES:
            ttk.Radiobutton(mode_row, text=m, value=m, variable=self.mode,
                            style="Mode.TRadiobutton",
                            command=self.on_mode_change).pack(side="left", padx=8)
        self.hint = ttk.Label(mode_card, text=MODE_HINT[self.mode.get()], style="Hint.TLabel",
                              wraplength=560, justify="left")
        self.hint.pack(anchor="w", pady=(6, 0))

        # Scrollable form
        self.canvas = tk.Canvas(root, highlightthickness=0, bg="#F1F5F9")
        sb = ttk.Scrollbar(root, orient="vertical", command=self.canvas.yview)
        self.form = ttk.Frame(self.canvas, padding=4)
        self.form_id = self.canvas.create_window((0, 0), window=self.form, anchor="nw")
        self.canvas.configure(yscrollcommand=sb.set)
        self.canvas.pack(side="left", fill="both", expand=True, padx=(16, 0), pady=4)
        sb.pack(side="right", fill="y", padx=(0, 8))
        self.form.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfig(self.form_id, width=e.width - 8))

        def _wheel(e):
            self.canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")

        self.canvas.bind_all("<MouseWheel>", _wheel)

        self.build_form(self.form)

        # Footer: generate + status
        footer = ttk.Frame(root, padding=(16, 6, 16, 12))
        footer.pack(fill="x")
        self.generate_btn = ttk.Button(footer, text="Generate", style="Accent.TButton",
                                       command=self.do_generate)
        self.generate_btn.pack(fill="x")
        ttk.Label(footer, textvariable=self.status, style="Status.TLabel",
                  wraplength=600, justify="left").pack(anchor="w", pady=(6, 0))
        result_row = ttk.Frame(footer)
        result_row.pack(fill="x", pady=(2, 0))
        ttk.Label(result_row, textvariable=self.result_path, style="Result.TLabel",
                  wraplength=440, justify="left").pack(side="left", fill="x", expand=True)
        ttk.Button(result_row, text="Open folder", style="Ghost.TButton",
                   command=lambda: open_folder(self.out_dir.get() or DEFAULT_OUT_DIR)).pack(side="right")
        ttk.Button(result_row, text="Inspect .crt...", style="Ghost.TButton",
                   command=self.show_cert_info).pack(side="right", padx=(0, 6))

        self.on_mode_change()

    # ----- form construction -----

    def labeled_entry(self, parent, label, default="", show=None):
        ttk.Label(parent, text=label, background="#FFFFFF").pack(anchor="w", pady=(8, 2))
        var = tk.StringVar(value=default)
        ttk.Entry(parent, textvariable=var, show=show or "", width=52).pack(fill="x")
        return var

    def picker_row(self, parent, label, default="", is_dir=False):
        ttk.Label(parent, text=label, background="#FFFFFF").pack(anchor="w", pady=(8, 2))
        row = ttk.Frame(parent)
        row.pack(fill="x")
        row.configure(style="Card.TFrame")
        var = tk.StringVar(value=default)
        ttk.Entry(row, textvariable=var).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Browse", style="Ghost.TButton",
                   command=lambda: self.browse(var, is_dir)).pack(side="right", padx=(6, 0))
        return var

    @staticmethod
    def browse(var: tk.StringVar, is_dir: bool):
        if is_dir:
            d = filedialog.askdirectory(initialdir=var.get() or os.getcwd())
            if d:
                var.set(d)
        else:
            f = filedialog.askopenfilename(initialdir=os.getcwd(),
                                           filetypes=(("PEM files", "*.crt *.key *.pem"), ("All", "*.*")))
            if f:
                var.set(f)

    def build_form(self, parent):
        # Card 2: identity
        id_card = ttk.LabelFrame(parent, text=" 2 - Certificate identity ", padding=12)
        id_card.pack(fill="x", pady=6)
        self.cn = self.labeled_entry(id_card, "Common Name (CN)  *", "example.com")
        self.cn_big_font = ("Segoe UI", 11)
        self.org = self.labeled_entry(id_card, "Organization (optional)", "")
        self.filename = self.labeled_entry(id_card, "File name (without extension)", "server")

        # Card 3: issuer (only for Server / Intermediate)
        self.issuer_card = ttk.LabelFrame(parent, text=" 3 - Issuer CA ", padding=12)
        self.issuer_card.pack(fill="x", pady=6)
        self.ca_cert = self.picker_row(self.issuer_card, "CA certificate (.crt)  *", "")
        self.ca_key = self.picker_row(self.issuer_card, "CA private key (.key)  *", "")

        # Card 4: hostnames
        self.san_card = ttk.LabelFrame(parent, text=" 4 - Hostnames (SAN) ", padding=12)
        self.san_card.pack(fill="x", pady=6)
        self.san_dns = self.labeled_entry(self.san_card, "DNS names (comma separated)",
                                          "example.com, www.example.com")
        self.san_ip = self.labeled_entry(self.san_card, "IP addresses (comma separated, optional)", "")

        # Card 5: options
        opt_card = ttk.LabelFrame(parent, text=" 5 - Options ", padding=12)
        opt_card.pack(fill="x", pady=6)
        ttk.Label(opt_card, text="Validity", background="#FFFFFF").pack(anchor="w", pady=(8, 2))
        self.validity = tk.StringVar(value="1 year - 825 days (browser limit)")
        ttk.Combobox(opt_card, textvariable=self.validity, values=list(VALIDITY_PRESETS),
                     state="readonly", width=50).pack(fill="x")
        ttk.Label(opt_card, text="Key", background="#FFFFFF").pack(anchor="w", pady=(8, 2))
        self.key_preset = tk.StringVar(value="RSA 2048 (recommended)")
        ttk.Combobox(opt_card, textvariable=self.key_preset, values=list(KEY_PRESETS),
                     state="readonly", width=50).pack(fill="x")
        self.out_dir = self.picker_row(opt_card, "Output folder", DEFAULT_OUT_DIR, is_dir=True)

        # Card 6: advanced (collapsed)
        self.adv_card = ttk.LabelFrame(parent, text=" 6 - Advanced (optional) ", padding=12)
        self.adv_card.pack(fill="x", pady=6)
        self.adv_toggle = ttk.Checkbutton(self.adv_card, text="Show advanced fields",
                                          variable=self.advanced_open,
                                          command=self.toggle_advanced)
        self.adv_toggle.pack(anchor="w")
        self.adv_body = ttk.Frame(self.adv_card)
        self.country = self.labeled_entry(self.adv_body, "Country code", "SA")
        self.state = self.labeled_entry(self.adv_body, "State / Province", "")
        self.city = self.labeled_entry(self.adv_body, "City", "")
        self.unit = self.labeled_entry(self.adv_body, "Unit (OU)", "")
        self.email = self.labeled_entry(self.adv_body, "Email", "")
        self.key_pwd = self.labeled_entry(self.adv_body, "Key password (optional)", "", show="*")
        self.ca_pwd = self.labeled_entry(self.adv_body, "CA key password (if encrypted)", "", show="*")

    def toggle_advanced(self):
        if self.advanced_open.get():
            self.adv_body.pack(fill="x", pady=(6, 0))
        else:
            self.adv_body.pack_forget()

    # ----- mode logic -----

    def on_mode_change(self):
        mode = self.mode.get()
        self.hint.configure(text=MODE_HINT.get(mode, ""))
        defaults = MODE_DEFAULTS.get(mode, {})
        if "cn" in defaults and not self.cn.get().strip():
            self.cn.set(defaults["cn"])
        # Do not overwrite user typing aggressively: only set empty or known defaults
        known_cns = {v["cn"] for v in MODE_DEFAULTS.values()}
        if self.cn.get().strip() in known_cns or not self.cn.get().strip():
            self.cn.set(defaults.get("cn", ""))
        self.filename.set(defaults.get("filename", "cert"))
        self.validity.set(defaults.get("validity", "1 year - 825 days (browser limit)"))

        if mode in ("Server cert", "Intermediate"):
            self.issuer_card.pack(fill="x", pady=6)
        else:
            self.issuer_card.pack_forget()

        if mode in ("Server cert", "Standalone"):
            self.san_card.pack(fill="x", pady=6)
            if mode == "Standalone":
                if self.san_dns.get().strip() in ("", "example.com, www.example.com"):
                    self.san_dns.set("localhost")
                if not self.san_ip.get().strip():
                    self.san_ip.set("127.0.0.1")
        else:
            self.san_card.pack_forget()

        self.generate_btn.configure(text={
            "Root CA": "Generate Root CA",
            "Server cert": "Generate server certificate",
            "Standalone": "Generate standalone certificate",
            "Intermediate": "Generate Intermediate CA",
        }.get(mode, "Generate"))
        self.set_status("Ready - %s." % mode)

    # ----- collectors -----

    def set_status(self, msg: str):
        self.status.set(msg)
        self.root.update_idletasks()

    def _key_spec(self) -> KeySpec:
        preset = KEY_PRESETS.get(self.key_preset.get(), ("rsa", 2048, "SECP256R1"))
        return KeySpec(key_type=preset[0], rsa_key_size=preset[1],
                       ec_curve=preset[2], password=self.key_pwd.get() or None)

    def _days(self) -> int:
        if self.validity.get() in VALIDITY_PRESETS:
            return VALIDITY_PRESETS[self.validity.get()]
        digits = "".join(c for c in self.validity.get() if c.isdigit())
        if digits:
            return max(1, int(digits))
        raise ValueError("Select a validity period.")

    def _subject(self) -> SubjectInfo:
        cn = self.cn.get().strip()
        if not cn:
            raise ValueError("Common Name (CN) is required.")
        return SubjectInfo(cn=cn, c=self.country.get().strip() or "SA",
                           st=self.state.get().strip(), l=self.city.get().strip(),
                           o=self.org.get().strip(), ou=self.unit.get().strip(),
                           email=self.email.get().strip())

    def _output(self) -> OutputSpec:
        return OutputSpec(out_dir=self.out_dir.get().strip() or DEFAULT_OUT_DIR,
                          filename=self.filename.get().strip() or "cert")

    # ----- generate -----

    def do_generate(self):
        mode = self.mode.get()
        self.generate_btn.state(["disabled"])
        self.set_status("Working...")
        try:
            if mode == "Root CA":
                out = issue_self_signed_ca(CaRequest(subject=self._subject(), key=self._key_spec(),
                                                     output=self._output(), days_valid=self._days()))
            elif mode == "Server cert":
                self._require_issuer()
                out = issue_signed_leaf(
                    LeafRequest(subject=self._subject(), key=self._key_spec(), output=self._output(),
                                san_dns=parse_san_list(self.san_dns.get()),
                                san_ips=parse_san_list(self.san_ip.get()),
                                days_valid=self._days()),
                    issuer_cert_path=self.ca_cert.get().strip(),
                    issuer_key_path=self.ca_key.get().strip(),
                    issuer_key_password=self.ca_pwd.get() or None)
            elif mode == "Standalone":
                out = issue_standalone(
                    LeafRequest(subject=self._subject(), key=self._key_spec(), output=self._output(),
                                san_dns=parse_san_list(self.san_dns.get()),
                                san_ips=parse_san_list(self.san_ip.get()),
                                days_valid=self._days()))
            elif mode == "Intermediate":
                self._require_issuer()
                out = issue_intermediate_ca(
                    CaRequest(subject=self._subject(), key=self._key_spec(),
                              output=self._output(), days_valid=self._days()),
                    issuer_cert_path=self.ca_cert.get().strip(),
                    issuer_key_path=self.ca_key.get().strip(),
                    issuer_key_password=self.ca_pwd.get() or None)
            else:
                raise ValueError("Unknown mode: %s" % mode)

            files = [out.key_file, out.cert_file] + ([out.chain_file] if out.chain_file else [])
            self.result_path.set("Created: " + "  |  ".join(os.path.basename(f) for f in files))
            self.set_status("Done - files saved in %s" % self._output().out_dir)
            messagebox.showinfo("Done", "Created:\n" + "\n".join(files))
        except Exception as e:
            self.set_status("Error: %s" % e)
            messagebox.showerror("Error", str(e) + "\n\n" + traceback.format_exc(limit=2))
        finally:
            self.generate_btn.state(["!disabled"])

    def _require_issuer(self):
        if not self.ca_cert.get().strip() or not self.ca_key.get().strip():
            raise ValueError("Select the issuer CA certificate and key first.")

    def show_cert_info(self):
        p = filedialog.askopenfilename(title="Select a .crt certificate",
                                       filetypes=(("Cert", "*.crt *.pem"), ("All", "*.*")))
        if not p:
            return
        try:
            c = load_cert(p)
            try:
                san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                san_txt = ", ".join(str(n.value) for n in san)
            except x509.ExtensionNotFound:
                san_txt = "-"
            info = ("File: %s\nSubject: %s\nIssuer: %s\nFrom: %s\nTo: %s\nSAN: %s"
                    % (p, c.subject.rfc4514_string(), c.issuer.rfc4514_string(),
                       c.not_valid_before_utc, c.not_valid_after_utc, san_txt))
            self.set_status("Inspected %s" % os.path.basename(p))
            messagebox.showinfo("Certificate info", info)
        except Exception as e:
            messagebox.showerror("Error", "Could not read certificate:\n%s" % e)


def main():
    root = tk.Tk()
    CertApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
