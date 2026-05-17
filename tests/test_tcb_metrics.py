"""Тесты метрик исходников ДВБ (LOC, цикломатика) для Регулятора."""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_REG = str(ROOT / "external_systems" / "regulator")
if _REG not in sys.path:
    sys.path.insert(0, _REG)


def test_count_loc_and_cyclomatic_trivial(tmp_path: Path) -> None:
    """Один файл, одна простая функция."""
    from regulator.tcb_metrics import compute_tcb_source_metrics

    pkg = tmp_path / "abu"
    pkg.mkdir()
    (pkg / "m.py").write_text(
        textwrap.dedent(
            '''
            def f():
                return 1
            '''
        ).strip(),
        encoding="utf-8",
    )
    loc, cc = compute_tcb_source_metrics(pkg)
    assert loc == 2  # две строки
    assert cc == 1  # одна функция, сложность 1


def test_cyclomatic_branches(tmp_path: Path) -> None:
    """If и BoolOp увеличивают суммарную сложность."""
    from regulator.tcb_metrics import compute_tcb_source_metrics

    pkg = tmp_path / "abu"
    pkg.mkdir()
    (pkg / "x.py").write_text(
        textwrap.dedent(
            '''
            def g(x):
                if x:
                    return 1 and 2
                return 0
            '''
        ).strip(),
        encoding="utf-8",
    )
    _loc, cc = compute_tcb_source_metrics(pkg)
    assert cc >= 3  # база + if + and


def test_tcb_source_cost_addon_matches_formula() -> None:
    """Аддитивная часть по LOC и K согласована с cost_model."""
    from regulator.cost_model import CC_COST_PER_POINT, LOC_COST_PER_LINE, tcb_source_cost_addon

    assert tcb_source_cost_addon(100, 50) == pytest.approx(
        100 * LOC_COST_PER_LINE + 50 * CC_COST_PER_POINT
    )
