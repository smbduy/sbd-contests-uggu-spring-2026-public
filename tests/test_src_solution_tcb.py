"""Покрытие и импорт ДВБ решения (src_solution.abu.tcb)."""

from __future__ import annotations


def test_tcb_health() -> None:
    from src_solution.abu.tcb.placeholder import tcb_health

    assert tcb_health() == "ok"
