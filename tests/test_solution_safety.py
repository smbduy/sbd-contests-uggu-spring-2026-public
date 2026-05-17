"""Тесты src_solution.abu.tcb.safety — импорт из src_solution (C12)."""

from __future__ import annotations

from src_solution.abu.tcb.safety import (
    check_safety_constraints,
    enforce_depth_cap,
    enforce_rpm_cap,
    should_emergency_stop,
)


def test_depth_cap_solution() -> None:
    """Проверка лимита глубины из решения."""
    assert enforce_depth_cap(10.0, 20.0) is True
    assert enforce_depth_cap(21.0, 20.0) is False


def test_rpm_cap_solution() -> None:
    """Проверка лимита оборотов из решения."""
    assert enforce_rpm_cap(100.0, 200.0) is True
    assert enforce_rpm_cap(300.0, 200.0) is False


def test_emergency_stop_solution() -> None:
    """Аварийный стоп из решения."""
    assert should_emergency_stop("high", 0.1) is True
    assert should_emergency_stop("low", 0.95) is True
    assert should_emergency_stop("low", 0.5) is False


def test_check_safety_constraints_solution() -> None:
    """Комплексная проверка из решения."""
    result = check_safety_constraints(
        depth_m=10.0, max_depth_m=20.0,
        rpm=100.0, max_rpm=200.0,
        risk="low", vibration_score=0.1,
    )
    assert result["status"] == "running"
