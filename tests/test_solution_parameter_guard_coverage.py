"""Дополнительные тесты покрытия parameter_guard.py и route_monitor.py."""

from __future__ import annotations

import json

from src_solution.abu.tcb.domain_guard import DomainGuard
from src_solution.abu.tcb.ipc import Event
from src_solution.abu.tcb.parameter_guard import ParameterGuard
from src_solution.abu.tcb.route_monitor import RouteMonitor, load_allows
from src_solution.abu.tcb.security_monitor import SecurityMonitor


# --- ParameterGuard: полный перебор валидных и невалидных кейсов ---


def test_start_mission_invalid_max_rpm_zero() -> None:
    """max_rpm = 0 невалиден."""
    guard = ParameterGuard()
    event = Event("a", "b", "start_mission", {"target_depth_m": 50.0, "max_rpm": 0})
    assert guard.check(event) is False


def test_start_mission_valid_without_max_rpm() -> None:
    """start_mission без max_rpm валиден."""
    guard = ParameterGuard()
    event = Event("a", "b", "start_mission", {"target_depth_m": 50.0})
    assert guard.check(event) is True


def test_tick_step_always_valid() -> None:
    """tick_step всегда валиден."""
    guard = ParameterGuard()
    event = Event("a", "b", "tick_step", {})
    assert guard.check(event) is True


def test_health_check_always_valid() -> None:
    """health_check всегда валиден."""
    guard = ParameterGuard()
    event = Event("a", "b", "health_check", {})
    assert guard.check(event) is True


def test_record_valid() -> None:
    """Валидная запись в журнал."""
    guard = ParameterGuard()
    event = Event("a", "b", "record", {"level": "INFO", "message": "test"})
    assert guard.check(event) is True


def test_record_message_too_long() -> None:
    """Сообщение длиннее 500 символов невалидно."""
    guard = ParameterGuard()
    event = Event("a", "b", "record", {"level": "INFO", "message": "x" * 501})
    assert guard.check(event) is False


def test_read_full_tail_valid_default() -> None:
    """read_full_tail с параметрами по умолчанию."""
    guard = ParameterGuard()
    event = Event("a", "b", "read_full_tail", {})
    assert guard.check(event) is True


def test_read_full_tail_invalid_zero() -> None:
    """max_lines = 0 невалиден."""
    guard = ParameterGuard()
    event = Event("a", "b", "read_full_tail", {"max_lines": 0})
    assert guard.check(event) is False


def test_regime_suggest_valid() -> None:
    """Валидный regime_suggest."""
    guard = ParameterGuard()
    event = Event("a", "b", "regime_suggest", {"depth_m": 10.0, "torque_nm": 1000.0})
    assert guard.check(event) is True


def test_regime_suggest_invalid_depth_negative() -> None:
    """Отрицательная глубина в regime_suggest."""
    guard = ParameterGuard()
    event = Event("a", "b", "regime_suggest", {"depth_m": -1.0, "torque_nm": 1000.0})
    assert guard.check(event) is False


def test_regime_suggest_invalid_torque_negative() -> None:
    """Отрицательный момент в regime_suggest."""
    guard = ParameterGuard()
    event = Event("a", "b", "regime_suggest", {"depth_m": 10.0, "torque_nm": -5.0})
    assert guard.check(event) is False


def test_anomaly_vibration_valid() -> None:
    """Валидный anomaly_vibration."""
    guard = ParameterGuard()
    event = Event("a", "b", "anomaly_vibration", {"samples": [1.0, 2.0]})
    assert guard.check(event) is True


def test_anomaly_vibration_not_list() -> None:
    """Не-list в samples."""
    guard = ParameterGuard()
    event = Event("a", "b", "anomaly_vibration", {"samples": "not a list"})
    assert guard.check(event) is False


def test_risk_flag_valid() -> None:
    """Валидный risk_flag."""
    guard = ParameterGuard()
    event = Event("a", "b", "risk_flag", {
        "vibration": 0.5, "pressure": 120.0, "depth_m": 10.0,
    })
    assert guard.check(event) is True


def test_risk_flag_invalid_vibration() -> None:
    """Не-число vibration."""
    guard = ParameterGuard()
    event = Event("a", "b", "risk_flag", {
        "vibration": "high", "pressure": 120.0, "depth_m": 10.0,
    })
    assert guard.check(event) is False


def test_risk_flag_invalid_pressure() -> None:
    """Не-число pressure."""
    guard = ParameterGuard()
    event = Event("a", "b", "risk_flag", {
        "vibration": 0.5, "pressure": None, "depth_m": 10.0,
    })
    assert guard.check(event) is False


def test_risk_flag_invalid_depth() -> None:
    """Не-число depth_m."""
    guard = ParameterGuard()
    event = Event("a", "b", "risk_flag", {
        "vibration": 0.5, "pressure": 120.0, "depth_m": "deep",
    })
    assert guard.check(event) is False


def test_ai_suggest_valid() -> None:
    """Валидный ai_suggest."""
    guard = ParameterGuard()
    event = Event("a", "b", "ai_suggest", {"depth_m": 5.0, "torque_nm": 3000.0})
    assert guard.check(event) is True


def test_ai_suggest_invalid_depth() -> None:
    """Невалидная глубина."""
    guard = ParameterGuard()
    event = Event("a", "b", "ai_suggest", {"depth_m": -1, "torque_nm": 3000.0})
    assert guard.check(event) is False


def test_ai_suggest_invalid_torque() -> None:
    """Невалидный момент."""
    guard = ParameterGuard()
    event = Event("a", "b", "ai_suggest", {"depth_m": 5.0, "torque_nm": -100})
    assert guard.check(event) is False


# --- RouteMonitor: покрытие load_allows и allows property ---


def test_route_monitor_load_allows_from_file(tmp_path) -> None:
    """Загрузка политик из JSON-файла через load_allows."""
    policy_file = tmp_path / "test_policies.json"
    policy_file.write_text(json.dumps({
        "allows": [{"from": "x", "to": "y", "func": "z"}],
    }))
    allows = load_allows(policy_file)
    assert ("x", "y", "z") in allows


def test_route_monitor_allows_property() -> None:
    """Свойство allows возвращает текущий whitelist."""
    allows = frozenset({("a", "b", "c")})
    monitor = RouteMonitor(allows=allows)
    assert monitor.allows == allows
