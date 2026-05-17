"""Интеграционный тест: event_log в src_solution + IPC-маршруты."""

from __future__ import annotations

from src_solution.abu.tcb.event_log import EventLevel, EventLog
from src_solution.abu.tcb.ipc import Event
from src_solution.abu.tcb.route_monitor import RouteMonitor


def test_event_log_with_ipc_event(tmp_path) -> None:
    """Событие IPC записывается в журнал через event_log."""
    log = EventLog(tmp_path)
    allows = frozenset({("http_api", "safety_controller", "tick_step")})
    monitor = RouteMonitor(allows=allows)
    event = Event("http_api", "safety_controller", "tick_step", {})
    if monitor.check(event):
        log.record(EventLevel.INFO, f"IPC_ALLOWED {event.source}->{event.destination}:{event.operation}")
    full = log.read_full_tail()
    assert "IPC_ALLOWED" in full
    assert "tick_step" in full


def test_event_log_denied_route(tmp_path) -> None:
    """Запрещённый маршрут записывается как ошибка."""
    log = EventLog(tmp_path)
    allows = frozenset({("http_api", "safety_controller", "tick_step")})
    monitor = RouteMonitor(allows=allows)
    event = Event("pseudo_ai", "safety_controller", "tick_step", {})
    if not monitor.check(event):
        log.record(EventLevel.ERROR, f"IPC_DENIED {event.source}->{event.destination}:{event.operation}")
    full = log.read_full_tail()
    assert "IPC_DENIED" in full
