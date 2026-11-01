"""Reusable widget factories and the shared visual language."""

import tkinter as tk

from ..config import PALETTE


class ThemeMixin:
    def _button(self, parent, text, command, primary=False, danger=False):
        if primary:
            bg, fg = PALETTE["accent"], PALETTE["on_accent"]
            abg, afg = "#63f29b", PALETTE["on_accent"]
            font = self.f_bold_md
        elif danger:
            bg, fg = PALETTE["danger"], PALETTE["on_danger"]
            abg, afg = PALETTE["danger_active"], PALETTE["on_danger_active"]
            font = self.f_bold_md
        else:
            bg, fg = PALETTE["surface_alt"], PALETTE["text"]
            abg, afg = PALETTE["border"], PALETTE["text_bright"]
            font = self.f_sm
        return tk.Button(
            parent, text=text, command=command,
            bg=bg, fg=fg, activebackground=abg, activeforeground=afg,
            disabledforeground=PALETTE["muted"],
            relief="flat", bd=0, highlightthickness=1,
            highlightbackground=PALETTE["border"], highlightcolor=PALETTE["border"],
            font=font, padx=14, pady=6, cursor="hand2", takefocus=0,
        )

    def _entry(self, parent, textvariable=None, width=10):
        return tk.Entry(
            parent, textvariable=textvariable, width=width,
            bg=PALETTE["input"], fg=PALETTE["text_bright"],
            insertbackground=PALETTE["accent"],
            disabledbackground=PALETTE["input"],
            relief="flat", bd=0, highlightthickness=1,
            highlightbackground=PALETTE["border"],
            highlightcolor=PALETTE["accent_soft"],
            font=self.f_sm,
        )

    def _panel(self, parent, **pack_kwargs):
        border = tk.Frame(parent, bg=PALETTE["border"])
        border.pack(**pack_kwargs)
        inner = tk.Frame(border, bg=PALETTE["surface"])
        inner.pack(fill="both", expand=True, padx=1, pady=1)
        return border, inner

    def _caption(self, parent, text):
        return tk.Label(
            parent, text=text, bg=PALETTE["surface"], fg=PALETTE["muted"],
            font=self.f_xs,
        )
