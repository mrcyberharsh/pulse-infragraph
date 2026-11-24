# Copyright (c) 2026 MR CYBER PULSE
# SPDX-License-Identifier: GPL-3.0-or-later

"""Stable Streamlit entry point; implementation lives in frontend/app.py."""
from pathlib import Path
import runpy


if __name__ == "__main__":
    runpy.run_path(str(Path(__file__).resolve().parent / "frontend" / "app.py"), run_name="__main__")
