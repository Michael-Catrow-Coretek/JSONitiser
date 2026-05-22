"""JSONitizerGUI — Tkinter front-end for JSONitizer (CYA Edition)."""

import json
import re
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
C_AMBER = "#ffd700"     # Placeholder key panel text


class JSONitizerGUI:
    """Main application window."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self._key_popup: tk.Toplevel | None = None
        self._popup_text: tk.Text | None = None
        self._configure_window()
        self._build_header()
        self._build_workspace()
        self._build_key_panel()
        self._build_action_row()

    # ------------------------------------------------------------------
    # Layout builders
    # ------------------------------------------------------------------

    def _configure_window(self) -> None:
        self.root.title("JSONitizer")
        self.root.geometry("1200x860")
        self.root.minsize(800, 620)
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

    def _build_key_panel(self) -> None:
        """Compact amber strip showing placeholder → original value after each run."""
        frame = tk.Frame(self.root, bg=C_BG)
        frame.pack(fill=tk.X, padx=24, pady=(0, 6))

        header = tk.Frame(frame, bg=C_BG)
        header.pack(fill=tk.X, pady=(0, 4))

        tk.Label(
            header,
            text="PLACEHOLDER KEY",
            bg=C_BG,
            fg=C_GREY,
            font=("Consolas", 9, "bold"),
        ).pack(side=tk.LEFT)

        tk.Button(
            header,
            text="↗  POP OUT",
            bg=C_BG,
            fg=C_GREY,
            font=("Consolas", 8),
            relief=tk.FLAT,
            cursor="hand2",
            activebackground=C_PANEL,
            activeforeground=C_AMBER,
            command=self._popout_key_panel,
            borderwidth=0,
            padx=6,
            pady=0,
        ).pack(side=tk.RIGHT)

        scroll_x = tk.Scrollbar(
            frame,
            orient=tk.HORIZONTAL,
            bg=C_BG,
            troughcolor=C_BG,
        )
        self.key_text = tk.Text(
            frame,
            bg=C_PANEL,
            fg=C_AMBER,
            font=("Consolas", 10),
            relief=tk.FLAT,
            wrap=tk.NONE,
            state=tk.DISABLED,
            height=6,
            borderwidth=0,
            highlightthickness=1,
            highlightbackground=C_BORDER,
            selectbackground="#5f5f00",
            selectforeground=C_WHITE,
            xscrollcommand=scroll_x.set,
        )
        scroll_x.configure(command=self.key_text.xview)
        scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        self.key_text.pack(fill=tk.X)

    def _render_key_panel(self, mapping: dict[str, str]) -> None:
        """Populate the key panel (and popup if open) with a sorted mapping view."""
        if not mapping:
            return

        def _sort_key(item: tuple[str, str]) -> tuple[str, int]:
            m = re.match(r"<([A-Z]+)_(\d+)>", item[1])
            return (m.group(1), int(m.group(2))) if m else (item[1], 0)

        lines = []
        for original, placeholder in sorted(mapping.items(), key=_sort_key):
            display = original if len(original) <= 64 else original[:61] + "..."
            lines.append(f"  {placeholder:<16}  →   {display}")

        content = "\n".join(lines)

        self.key_text.configure(state=tk.NORMAL)
        self.key_text.delete("1.0", tk.END)
        self.key_text.insert("1.0", content)
        self.key_text.configure(state=tk.DISABLED)

        # Keep pop-out window in sync if it is already open.
        if self._key_popup is not None and self._key_popup.winfo_exists():
            self._popup_text.configure(state=tk.NORMAL)
            self._popup_text.delete("1.0", tk.END)
            self._popup_text.insert("1.0", content)
            self._popup_text.configure(state=tk.DISABLED)

    def _popout_key_panel(self) -> None:
        """Open a detached, resizable Toplevel showing the full placeholder mapping."""
        # If already open, just bring it to the front.
        if self._key_popup is not None and self._key_popup.winfo_exists():
            self._key_popup.lift()
            self._key_popup.focus_force()
            return

        popup = tk.Toplevel(self.root)
        popup.title("Placeholder Key — JSONitizer")
        popup.geometry("720x420")
        popup.minsize(400, 200)
        popup.configure(bg=C_BG)
        popup.resizable(True, True)
        self._key_popup = popup

        frame = tk.Frame(popup, bg=C_BG)
        frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        scroll_y = tk.Scrollbar(frame, orient=tk.VERTICAL, bg=C_BG, troughcolor=C_BG)
        scroll_x = tk.Scrollbar(frame, orient=tk.HORIZONTAL, bg=C_BG, troughcolor=C_BG)

        self._popup_text = tk.Text(
            frame,
            bg=C_PANEL,
            fg=C_AMBER,
            font=("Consolas", 11),
            relief=tk.FLAT,
            wrap=tk.NONE,
            state=tk.DISABLED,
            borderwidth=0,
            highlightthickness=1,
            highlightbackground=C_BORDER,
            selectbackground="#5f5f00",
            selectforeground=C_WHITE,
            yscrollcommand=scroll_y.set,
            xscrollcommand=scroll_x.set,
        )
        scroll_y.configure(command=self._popup_text.yview)
        scroll_x.configure(command=self._popup_text.xview)

        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)
        self._popup_text.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x.grid(row=1, column=0, sticky="ew")

        # Copy current content from the embedded panel.
        current = self.key_text.get("1.0", tk.END).rstrip()
        if current:
            self._popup_text.configure(state=tk.NORMAL)
            self._popup_text.insert("1.0", current)
            self._popup_text.configure(state=tk.DISABLED)

        def _on_close() -> None:
            self._key_popup = None
            self._popup_text = None
            popup.destroy()

        popup.protocol("WM_DELETE_WINDOW", _on_close)

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

        self._render_key_panel(engine.mapping)

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
        self.key_text.configure(state=tk.NORMAL)
        self.key_text.delete("1.0", tk.END)
        self.key_text.configure(state=tk.DISABLED)
        if self._key_popup is not None and self._key_popup.winfo_exists():
            self._popup_text.configure(state=tk.NORMAL)
            self._popup_text.delete("1.0", tk.END)
            self._popup_text.configure(state=tk.DISABLED)
