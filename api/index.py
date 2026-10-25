from __future__ import annotations

import os
import sys
from pathlib import Path

# Mark Vercel serverless environment
os.environ.setdefault("VERCEL", "1")

# Ensure repository root is on sys.path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.api import app  # noqa: E402

# Export app for Vercel Serverless Function handler
__all__ = ["app"]
