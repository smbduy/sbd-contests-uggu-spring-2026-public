"""Тесты SG_ADS_Controlled_operations — контролируемые операции."""

from __future__ import annotations

import pytest

from src_solution.abu.tcb.safety import (
    check_safety_constraints,
    should_emergency_stop,
)


@pytest.mark.security
def test_emergency_stop_on_high_risk() -> None:
    """Высокий риск вызывает аварийную остановку."""
    assert should_emergency_stop("high", 0.1) is True


@pytest.mark.security
def test_emergency_stop_on_vibration_threshold() -> None:
    """Вибрация выше порога вызывает аварийную остановку."""
    assert should_emergency_stop("low", 0.95) is True


@pytest.mark.security
def test_no_emergency_when_normal() -> None:
    """Нормальный режим — без аварийной остановки."""
    assert should_emergency_stop("low", 0.1) is False
    assert should_emergency_stop("medium", 0.5) is False


@pytest.mark.security
def test_check_safety_constraints_emergency() -> None:
    """Комплексная проверка: высокий риск = emergency."""
    result = check_safety_constraints(
        depth_m=10.0, max_depth_m=20.0,
        rpm=100.0, max_rpm=200.0,
        risk="high", vibration_score=0.1,
    )
    assert result["emergency"] is True
    assert result["status"] == "emergency"


@pytest.mark.security
def test_check_safety_constraints_depth_exceeded() -> None:
    """Комплексная проверка: превышение глубины."""
    result = check_safety_constraints(
        depth_m=25.0, max_depth_m=20.0,
        rpm=100.0, max_rpm=200.0,
        risk="low", vibration_score=0.1,
    )
    assert result["depth_ok"] is False
    assert result["status"] == "stopped_depth"


@pytest.mark.security
def test_check_safety_constraints_rpm_exceeded() -> None:
    """Комплексная проверка: превышение оборотов."""
    result = check_safety_constraints(
        depth_m=10.0, max_depth_m=20.0,
        rpm=300.0, max_rpm=200.0,
        risk="low", vibration_score=0.1,
    )
    assert result["rpm_ok"] is False
    assert result["status"] == "stopped_rpm"


@pytest.mark.security
def test_check_safety_constraints_running() -> None:
    """Комплексная проверка: нормальный режим."""
    result = check_safety_constraints(
        depth_m=10.0, max_depth_m=20.0,
        rpm=100.0, max_rpm=200.0,
        risk="low", vibration_score=0.1,
    )
    assert result["depth_ok"] is True
    assert result["rpm_ok"] is True
    assert result["emergency"] is False
    assert result["status"] == "running"
