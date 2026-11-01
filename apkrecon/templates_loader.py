"""Loaders for the files under apkrecon/templates/."""

import os

from .config import TEMPLATES_DIR


def load_template(name):
    """Return the text of a template file shipped with the package."""
    path = os.path.join(TEMPLATES_DIR, name)
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


__all__ = ["load_template"]
