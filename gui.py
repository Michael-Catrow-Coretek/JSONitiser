"""JSONitizerGUI — Tkinter front-end for JSONitizer (CYA Edition)."""

import json
import tkinter as tk
from tkinter import messagebox

from engine import JSONitizerEngine

# ---------------------------------------------------------------------------
# Colour palette — SOC Dark Mode
# ---------------------------------------------------------------------------
C_BG = "#1e1e1e"        # Window / frame background
C_PANEL = "#2d2d2d"     # Text-area background
C_GREEN = "#00ff41"     # Cyber-green  (output text, title)
C_GREY = "#888888"      # Muted panel labels
C_WHITE = "#ffffff"     # Input text
C_BTN_GREEN = "#00c136" # Sanitize button fill
C_BTN_GREY = "#3c3c3c"  # Secondary button fill
C_BTN_RED = "#ff4444"   # Clear-all label colour
C_BORDER = "#444444"    # Text-area border highlight


class JSONitizerGUI:
    """Main application window."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self._configure_window()
        self._build_header()
        self._build_workspace()
        self._build_action_row()

    # ------------------------------------------------------------------
    # Layout builders
    # ------------------------------------------------------------------

    def _configure_window(self) -> None:
        self.root.title("JSONitizer")
        self.root.geometry("1200x750")
        self.root.minsize(800, 500)
        self.root.configure(bg=C_BG)

    def _build_header(self) -> None:
        hdr = tk.Frame(self.root, bg=C_BG)
        hdr.pack(fill=tk.X, padx=24, pady=(16, 4))

        tk.Label(
            hdr,
            text="JSONitizer",
            bg=C_BG,
            fg=C_GREEN,
            font=("Consolas", 28, "bold"),
        ).pack()

        tk.Label(
            hdr,
            text="Because the LLM doesn't need to know who's about to get an HR violation.",
            bg=C_BG,
            fg=C_GREY,
            font=("Consolas", 10, "italic"),
        ).pack()

    def _build_workspace(self) -> None:
        outer = tk.Frame(self.root, bg=C_BG)
        outer.pack(fill=tk.BOTH, expand=True, padx=24, pady=8)

        self.input_text = self._make_panel(
            outer,
            label="RAW ELASTIC JSON",
            fg=C_WHITE,
            readonly=False,
            side=tk.LEFT,
            padx=(0, 6),
        )

        self.output_text = self._make_panel(
            outer,
            label="SANITIZED OUTPUT  (IPs PRESERVED)",
            fg=C_GREEN,
            readonly=True,
            side=tk.LEFT,
            padx=(6, 0),
        )

    def _make_panel(
        self,
        parent: tk.Frame,
        label: str,
        fg: str,
        readonly: bool,
        side: str,
        padx: tuple[int, int],
    ) -> tk.Text:
        """Build a labelled text panel with horizontal and vertical scrollbars."""
        frame = tk.Frame(parent, bg=C_BG)
        frame.pack(side=side, fill=tk.BOTH, expand=True, padx=padx)

        tk.Label(
            frame,
            text=label,
            bg=C_BG,
            fg=C_GREY,
            font=("Consolas", 9, "bold"),
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 4))

        widget = tk.Text(
            frame,
            bg=C_PANEL,
            fg=fg,
            insertbackground=fg,
            font=("Consolas", 10),
            relief=tk.FLAT,
            wrap=tk.NONE,
            undo=(not readonly),
            state=tk.DISABLED if readonly else tk.NORMAL,
            borderwidth=0,
            highlightthickness=1,
            highlightbackground=C_BORDER,
            selectbackground="#005f5f",
            selectforeground=C_WHITE,
        )

        scroll_y = tk.Scrollbar(
            frame, command=widget.yview, bg=C_BG, troughcolor=C_BG
        )
        scroll_x = tk.Scrollbar(
            frame,
            orient=tk.HORIZONTAL,
            command=widget.xview,
            bg=C_BG,
            troughcolor=C_BG,
        )
        widget.configure(
            yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set
        )

        frame.grid_rowconfigure(1, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        widget.grid(row=1, column=0, sticky="nsew")
        scroll_y.grid(row=1, column=1, sticky="ns")
        scroll_x.grid(row=2, column=0, sticky="ew")

        return widget

    def _build_action_row(self) -> None:
        row = tk.Frame(self.root, bg=C_BG)
        row.pack(fill=tk.X, padx=24, pady=(4, 16))

        tk.Button(
            row,
            text="SANITIZE & CLEAN",
            bg=C_BTN_GREEN,
            fg=C_BG,
            activebackground="#009929",
            activeforeground=C_BG,
            font=("Consolas", 11, "bold"),
            relief=tk.FLAT,
            padx=20,
            pady=8,
            cursor="hand2",
            command=self._sanitize_cmd,
        ).pack(side=tk.LEFT, padx=(0, 8))

        self._copy_btn = tk.Button(
            row,
            text="COPY TO CLIPBOARD",
            bg=C_BTN_GREY,
            fg=C_WHITE,
            activebackground="#555555",
            activeforeground=C_WHITE,
            font=("Consolas", 11),
            relief=tk.FLAT,
            padx=20,
            pady=8,
            cursor="hand2",
            command=self._copy_cmd,
        )
        self._copy_btn.pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(
            row,
            text="CLEAR ALL",
            bg=C_BTN_GREY,
            fg=C_BTN_RED,
            activebackground="#555555",
            activeforeground=C_BTN_RED,
            font=("Consolas", 11),
            relief=tk.FLAT,
            padx=20,
            pady=8,
            cursor="hand2",
            command=self._clear_cmd,
        ).pack(side=tk.LEFT)

    # ------------------------------------------------------------------
    # Button handlers
    # ------------------------------------------------------------------

    def _sanitize_cmd(self) -> None:
        raw = self.input_text.get("1.0", tk.END).strip()
        if not raw:
            return

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            messagebox.showerror(
                "Invalid JSON",
                f"The input does not contain valid JSON.\n\nDetail: {exc}",
                parent=self.root,
            )
            return

        # Re-instantiate for stateless, session-free operation.
        engine = JSONitizerEngine()
        sanitized = engine.sanitize(data)
        output = json.dumps(sanitized, indent=2, ensure_ascii=False)

        self.output_text.configure(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert("1.0", output)
        self.output_text.configure(state=tk.DISABLED)

    def _copy_cmd(self) -> None:
        content = self.output_text.get("1.0", tk.END).strip()
        if not content:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        # Keep clipboard populated even after the window closes.
        self.root.update()

        original = self._copy_btn.cget("text")
        self._copy_btn.configure(text="COPIED!")
        self.root.after(2000, lambda: self._copy_btn.configure(text=original))

    def _clear_cmd(self) -> None:
        self.input_text.delete("1.0", tk.END)
        self.output_text.configure(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.configure(state=tk.DISABLED)
