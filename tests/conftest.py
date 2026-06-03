from __future__ import annotations

import sys
from pathlib import Path

# Ensure the aegisflow package under src/ is importable during test runs
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
