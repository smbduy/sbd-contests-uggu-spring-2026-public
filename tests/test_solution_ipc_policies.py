"""Тесты security_monitor и политик IPC из src_solution (C18)."""

from __future__ import annotations

from src_solution.abu.tcb.domain_guard import DomainGuard
from src_solution.abu.tcb.ipc import Event
from src_solution.abu.tcb.parameter_guard import ParameterGuard
from src_solution.abu.tcb.route_monitor import RouteMonitor
from src_solution.abu.tcb.security_monitor import SecurityMonitor


def test_security_monitor_policies_whitelist() -> None:
    """SecurityMonitor пропускает только whitelisted маршруты."""
    allows = frozenset({
        ("http_api", "safety_controller", "start_mission"),
        ("safety_controller", "pseudo_ai", "risk_flag"),
    })
    monitor = SecurityMonitor(
        route_monitor=RouteMonitor(allows=allows),
    )
    ok_event = Event(
        "http_api", "safety_controller", "start_mission",
        {"target_depth_m": 50.0, "max_rpm": 200.0},
    )
    assert monitor.check(ok_event) is True

    bad_event = Event("pseudo_ai", "safety_controller", "tick_step", {})
    assert monitor.check(bad_event) is False


def test_security_monitor_parameter_validation() -> None:
    """ParameterGuard отклоняет невалидные параметры."""
    allows = frozenset({("http_api", "safety_controller", "start_mission")})
    monitor = SecurityMonitor(
        route_monitor=RouteMonitor(allows=allows),
    )
    bad_params = Event(
        "http_api", "safety_controller", "start_mission",
        {"target_depth_m": -1.0},
    )
    assert monitor.check(bad_params) is False


def test_security_monitor_domain_isolation() -> None:
    """DomainGuard блокирует прямой доступ pseudo_ai -> safety_controller."""
    guard = DomainGuard()
    event = Event("pseudo_ai", "safety_controller", "tick_step", {})
    assert guard.check(event) is False
