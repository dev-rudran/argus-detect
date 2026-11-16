"""Module entry point so ``python -m argus`` behaves like the ``argus`` command."""

from __future__ import annotations

import sys

from argus.cli import main

if __name__ == "__main__":
    sys.exit(main())
