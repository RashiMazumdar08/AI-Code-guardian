#!/usr/bin/env python3
"""Backward-compat entry point. `python main.py scan <path>` still works;
the canonical CLI is now `python -m guardian scan <path>`."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guardian.cli import main  # noqa: E402

raise SystemExit(main())
