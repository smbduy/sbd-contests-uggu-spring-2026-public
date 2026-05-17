"""Калибровка скрипта оценки: итог в диапазоне 10–20 на базовой заготовке (без повторного pytest)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_evaluate_contest_score_calibration_no_pytest() -> None:
    """Быстрая проверка: сумма критериев и шкала 10–20 для текущего дерева репозитория."""
    script = ROOT / "scripts" / "evaluate_contest_score.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--no-pytest", "--json"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    disp = data["display_score_10_20"]
    assert 10.0 <= disp <= 20.0, f"калибровка вне [10, 20]: {disp}"
