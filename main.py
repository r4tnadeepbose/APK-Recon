#!/usr/bin/env python3
"""APK-Recon launcher.

Run this file (or `python main.py`) to start the desktop application.
All scanning, reporting and UI code lives in the ``apkrecon`` package.
"""

import tkinter as tk

from apkrecon.ui.app import APKReconGUI


def main():
    root = tk.Tk()
    APKReconGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
