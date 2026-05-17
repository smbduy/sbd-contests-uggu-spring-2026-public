"""Тесты доменов и изоляции в src_solution (C19)."""

from __future__ import annotations

from src_solution.abu.tcb.domain_guard import DomainGuard
from src_solution.abu.tcb.ipc import Event
from src_solution.abu.tcb.parameter_guard import ParameterGuard


def test_domain_guard_blocks_unauthorized_egress() -> None:
    """event_log не может отправлять сообщения pseudo_ai."""
    guard = DomainGuard()
    event = Event("event_log", "pseudo_ai", "regime_suggest", {})
    assert guard.check_egress(event) is False


def test_domain_guard_blocks_unauthorized_ingress() -> None:
    """pseudo_ai не может отправлять команды safety_controller."""
    guard = DomainGuard()
    event = Event("pseudo_ai", "safety_controller", "tick_step", {})
    assert guard.check_ingress(event) is False


def test_domain_guard_allows_authorized() -> None:
    """safety_controller может запросить pseudo_ai."""
    guard = DomainGuard()
    event = Event("safety_controller", "pseudo_ai", "risk_flag", {})
    assert guard.check(event) is True


def test_parameter_guard_validates_record() -> None:
    """ParameterGuard валидирует запись в журнал."""
    guard = ParameterGuard()
    valid = Event("safety_controller", "event_log", "record", {
        "level": "INFO",
        "message": "test event",
    })
    assert guard.check(valid) is True

    invalid_level = Event("safety_controller", "event_log", "record", {
        "level": "INVALID",
        "message": "test",
    })
    assert guard.check(invalid_level) is False


def test_parameter_guard_request_response_pattern() -> None:
    """Шаблон request/response: валидный запрос и ответ."""
    guard = ParameterGuard()
    request = Event("http_api", "safety_controller", "start_mission", {
        "target_depth_m": 50.0,
        "max_rpm": 200.0,
    })
    assert guard.check(request) is True
