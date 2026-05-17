"""Тесты src_solution: security_monitor + policies (C12, C18)."""

from __future__ import annotations

from src_solution.abu.tcb.ipc import Event
from src_solution.abu.tcb.route_monitor import RouteMonitor
from src_solution.abu.tcb.security_monitor import SecurityMonitor


def test_route_monitor_default_deny() -> None:
    """Default deny: пустой whitelist отклоняет всё."""
    monitor = RouteMonitor(allows=frozenset())
    event = Event("http_api", "safety_controller", "tick_step", {})
    assert monitor.check(event) is False


def test_route_monitor_allows_whitelisted() -> None:
    """Whitelisted маршрут разрешён."""
    allows = frozenset({("http_api", "safety_controller", "tick_step")})
    monitor = RouteMonitor(allows=allows)
    event = Event("http_api", "safety_controller", "tick_step", {})
    assert monitor.check(event) is True


def test_security_monitor_rejects_unauthorized_route() -> None:
    """SecurityMonitor отклоняет несанкционированный маршрут."""
    allows = frozenset({("http_api", "safety_controller", "tick_step")})
    monitor = SecurityMonitor(
        route_monitor=RouteMonitor(allows=allows),
    )
    event = Event("pseudo_ai", "safety_controller", "tick_step", {})
    assert monitor.check(event) is False
