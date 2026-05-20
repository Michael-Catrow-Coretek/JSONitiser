"""Entry point for JSONitizer (CYA Edition)."""

import tkinter as tk

from gui import JSONitizerGUI


def main() -> None:
    root = tk.Tk()
    JSONitizerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
