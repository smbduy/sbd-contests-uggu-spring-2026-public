"""Тесты SecurityMonitor, политик IPC и маршрутов (C18)."""

from __future__ import annotations

import pytest

from src_solution.abu.tcb.domain_guard import DomainGuard
from src_solution.abu.tcb.ipc import Event
from src_solution.abu.tcb.parameter_guard import ParameterGuard
from src_solution.abu.tcb.route_monitor import RouteMonitor
from src_solution.abu.tcb.security_monitor import SecurityMonitor


# --- RouteMonitor ---

class TestRouteMonitor:
    """Тесты маршрутного монитора (default deny + whitelist)."""

    @pytest.mark.security
    def test_allowed_route_passes(self) -> None:
        """Разрешённый маршрут проходит проверку."""
        allows = frozenset({("http_api", "safety_controller", "tick_step")})
        monitor = RouteMonitor(allows=allows)
        event = Event("http_api", "safety_controller", "tick_step", {})
        assert monitor.check(event) is True

    @pytest.mark.security
    def test_blocked_route_denied(self) -> None:
        """Неразрешённый маршрут отклонён (default deny)."""
        allows = frozenset({("http_api", "safety_controller", "tick_step")})
        monitor = RouteMonitor(allows=allows)
        event = Event("http_api", "event_log", "record", {})
        assert monitor.check(event) is False

    @pytest.mark.security
    def test_non_event_denied(self) -> None:
        """Не-Event объект всегда отклонён."""
        allows = frozenset({("http_api", "safety_controller", "tick_step")})
        monitor = RouteMonitor(allows=allows)
        assert monitor.check("not an event") is False

    @pytest.mark.security
    def test_allows_property(self) -> None:
        """Свойство allows возвращает текущий whitelist."""
        allows = frozenset({("a", "b", "c")})
        monitor = RouteMonitor(allows=allows)
        assert monitor.allows == allows

    @pytest.mark.security
    def test_load_allows_from_file(self, tmp_path) -> None:
        """Загрузка политик из JSON-файла."""
        import json
        policy_file = tmp_path / "test_policies.json"
        policy_file.write_text(json.dumps({
            "allows": [{"from": "x", "to": "y", "func": "z"}],
        }))
        allows = RouteMonitor(policies_path=policy_file).allows
        assert ("x", "y", "z") in allows


# --- DomainGuard ---

class TestDomainGuard:
    """Тесты доменных политик (egress/ingress)."""

    @pytest.mark.security
    def test_egress_allowed(self) -> None:
        """Разрешённый исходящий маршрут."""
        guard = DomainGuard()
        event = Event("safety_controller", "pseudo_ai", "regime_suggest", {})
        assert guard.check_egress(event) is True

    @pytest.mark.security
    def test_egress_blocked(self) -> None:
        """Запрещённый исходящий маршрут."""
        guard = DomainGuard()
        event = Event("event_log", "pseudo_ai", "regime_suggest", {})
        assert guard.check_egress(event) is False

    @pytest.mark.security
    def test_ingress_blocked_direct(self) -> None:
        """Прямой вызов pseudo_ai -> safety_controller запрещён."""
        guard = DomainGuard()
        event = Event("pseudo_ai", "safety_controller", "tick_step", {})
        assert guard.check_ingress(event) is False


# --- ParameterGuard ---

class TestParameterGuard:
    """Тесты валидации параметров."""

    @pytest.mark.security
    def test_valid_start_mission(self) -> None:
        """Валидные параметры start_mission."""
        guard = ParameterGuard()
        event = Event("http_api", "safety_controller", "start_mission", {
            "target_depth_m": 50.0,
            "max_rpm": 200.0,
        })
        assert guard.check(event) is True

    @pytest.mark.security
    def test_invalid_start_mission_depth(self) -> None:
        """Невалидная глубина в start_mission."""
        guard = ParameterGuard()
        event = Event("http_api", "safety_controller", "start_mission", {
            "target_depth_m": -1.0,
        })
        assert guard.check(event) is False

    @pytest.mark.security
    def test_unknown_operation_denied(self) -> None:
        """Неизвестная операция отклонена (default deny)."""
        guard = ParameterGuard()
        event = Event("http_api", "safety_controller", "unknown_op", {})
        assert guard.check(event) is False

    @pytest.mark.security
    def test_start_mission_depth_over_200(self) -> None:
        """Глубина > 200 невалидна."""
        guard = ParameterGuard()
        event = Event("a", "b", "start_mission", {
            "target_depth_m": 250.0,
        })
        assert guard.check(event) is False

    @pytest.mark.security
    def test_start_mission_invalid_max_rpm(self) -> None:
        """Невалидный max_rpm."""
        guard = ParameterGuard()
        event = Event("a", "b", "start_mission", {
            "target_depth_m": 50.0,
            "max_rpm": -10.0,
        })
        assert guard.check(event) is False

    @pytest.mark.security
    def test_tick_step_always_valid(self) -> None:
        """tick_step всегда валиден."""
        guard = ParameterGuard()
        event = Event("a", "b", "tick_step", {})
        assert guard.check(event) is True

    @pytest.mark.security
    def test_no_params_operations(self) -> None:
        """get_status, health_check, ring_snapshot всегда валидны."""
        guard = ParameterGuard()
        for op in ("get_status", "health_check", "ring_snapshot"):
            event = Event("a", "b", op, {})
            assert guard.check(event) is True

    @pytest.mark.security
    def test_record_invalid_level(self) -> None:
        """Невалидный уровень в record."""
        guard = ParameterGuard()
        event = Event("a", "b", "record", {
            "level": "BAD", "message": "test",
        })
        assert guard.check(event) is False

    @pytest.mark.security
    def test_record_empty_message(self) -> None:
        """Пустое сообщение в record."""
        guard = ParameterGuard()
        event = Event("a", "b", "record", {
            "level": "INFO", "message": "",
        })
        assert guard.check(event) is False

    @pytest.mark.security
    def test_record_non_string_message(self) -> None:
        """Не-строка в message."""
        guard = ParameterGuard()
        event = Event("a", "b", "record", {
            "level": "INFO", "message": 123,
        })
        assert guard.check(event) is False

    @pytest.mark.security
    def test_read_full_tail_valid(self) -> None:
        """Валидный read_full_tail."""
        guard = ParameterGuard()
        event = Event("a", "b", "read_full_tail", {"max_lines": 100})
        assert guard.check(event) is True

    @pytest.mark.security
    def test_read_full_tail_invalid_max_lines(self) -> None:
        """Невалидный max_lines."""
        guard = ParameterGuard()
        event = Event("a", "b", "read_full_tail", {"max_lines": -1})
        assert guard.check(event) is False

    @pytest.mark.security
    def test_regime_suggest_invalid_depth(self) -> None:
        """Невалидная глубина в regime_suggest."""
        guard = ParameterGuard()
        event = Event("a", "b", "regime_suggest", {
            "depth_m": -1, "torque_nm": 1000.0,
        })
        assert guard.check(event) is False

    @pytest.mark.security
    def test_regime_suggest_invalid_torque(self) -> None:
        """Невалидный момент в regime_suggest."""
        guard = ParameterGuard()
        event = Event("a", "b", "regime_suggest", {
            "depth_m": 10.0, "torque_nm": -5,
        })
        assert guard.check(event) is False

    @pytest.mark.security
    def test_anomaly_vibration_valid(self) -> None:
        """Валидные samples в anomaly_vibration."""
        guard = ParameterGuard()
        event = Event("a", "b", "anomaly_vibration", {
            "samples": [1.0, 2.0],
        })
        assert guard.check(event) is True

    @pytest.mark.security
    def test_anomaly_vibration_not_list(self) -> None:
        """Не-list в samples."""
        guard = ParameterGuard()
        event = Event("a", "b", "anomaly_vibration", {
            "samples": "not a list",
        })
        assert guard.check(event) is False

    @pytest.mark.security
    def test_risk_flag_valid(self) -> None:
        """Валидные параметры risk_flag."""
        guard = ParameterGuard()
        event = Event("a", "b", "risk_flag", {
            "vibration": 0.5, "pressure": 120.0, "depth_m": 10.0,
        })
        assert guard.check(event) is True

    @pytest.mark.security
    def test_risk_flag_invalid_vibration(self) -> None:
        """Не-число vibration в risk_flag."""
        guard = ParameterGuard()
        event = Event("a", "b", "risk_flag", {
            "vibration": "high", "pressure": 120.0, "depth_m": 10.0,
        })
        assert guard.check(event) is False

    @pytest.mark.security
    def test_risk_flag_invalid_pressure(self) -> None:
        """Не-число pressure в risk_flag."""
        guard = ParameterGuard()
        event = Event("a", "b", "risk_flag", {
            "vibration": 0.5, "pressure": None, "depth_m": 10.0,
        })
        assert guard.check(event) is False

    @pytest.mark.security
    def test_risk_flag_invalid_depth(self) -> None:
        """Не-число depth_m в risk_flag."""
        guard = ParameterGuard()
        event = Event("a", "b", "risk_flag", {
            "vibration": 0.5, "pressure": 120.0, "depth_m": "deep",
        })
        assert guard.check(event) is False

    @pytest.mark.security
    def test_ai_suggest_valid(self) -> None:
        """Валидные параметры ai_suggest."""
        guard = ParameterGuard()
        event = Event("a", "b", "ai_suggest", {
            "depth_m": 5.0, "torque_nm": 3000.0,
        })
        assert guard.check(event) is True

    @pytest.mark.security
    def test_ai_suggest_invalid_depth(self) -> None:
        """Невалидная глубина в ai_suggest."""
        guard = ParameterGuard()
        event = Event("a", "b", "ai_suggest", {
            "depth_m": -1, "torque_nm": 3000.0,
        })
        assert guard.check(event) is False

    @pytest.mark.security
    def test_ai_suggest_invalid_torque(self) -> None:
        """Невалидный момент в ai_suggest."""
        guard = ParameterGuard()
        event = Event("a", "b", "ai_suggest", {
            "depth_m": 5.0, "torque_nm": -100,
        })
        assert guard.check(event) is False

    @pytest.mark.security
    def test_start_mission_valid_without_max_rpm(self) -> None:
        """start_mission без max_rpm валиден."""
        guard = ParameterGuard()
        event = Event("a", "b", "start_mission", {
            "target_depth_m": 50.0,
        })
        assert guard.check(event) is True

    @pytest.mark.security
    def test_custom_policies(self) -> None:
        """Пользовательские политики."""
        guard = ParameterGuard(policies={
            "custom_op": lambda e: e.parameters.get("key") == "val",
        })
        ok = Event("a", "b", "custom_op", {"key": "val"})
        bad = Event("a", "b", "custom_op", {"key": "wrong"})
        assert guard.check(ok) is True
        assert guard.check(bad) is False


# --- SecurityMonitor (интеграция) ---

class TestSecurityMonitor:
    """Интеграционные тесты монитора безопасности."""

    @pytest.mark.security
    def test_full_check_allowed(self) -> None:
        """Разрешённый маршрут проходит все три слоя."""
        allows = frozenset({
            ("http_api", "safety_controller", "start_mission"),
        })
        monitor = SecurityMonitor(
            route_monitor=RouteMonitor(allows=allows),
        )
        event = Event(
            "http_api", "safety_controller",
            "start_mission",
            {
                "target_depth_m": 50.0,
                "max_rpm": 200.0,
            },
        )
        assert monitor.check(event) is True

    @pytest.mark.security
    def test_full_check_route_denied(self) -> None:
        """Неразрешённый маршрут отклонён на первом слое."""
        allows = frozenset({("http_api", "safety_controller", "tick_step")})
        monitor = SecurityMonitor(
            route_monitor=RouteMonitor(allows=allows),
        )
        event = Event("pseudo_ai", "safety_controller", "tick_step", {})
        assert monitor.check(event) is False

    @pytest.mark.security
    def test_unauthorized_route_from_pseudo_ai_to_safety(self) -> None:
        """pseudo_ai не может напрямую отправлять команды safety_controller."""
        allows = frozenset({
            ("http_api", "safety_controller", "tick_step"),
            ("safety_controller", "pseudo_ai", "risk_flag"),
        })
        monitor = SecurityMonitor(
            route_monitor=RouteMonitor(allows=allows),
        )
        event = Event("pseudo_ai", "safety_controller", "tick_step", {})
        assert monitor.check(event) is False

    @pytest.mark.security
    def test_check_route_method(self) -> None:
        """check_route проверяет только маршрутный слой."""
        allows = frozenset({
            ("http_api", "safety_controller", "tick_step"),
        })
        monitor = SecurityMonitor(
            route_monitor=RouteMonitor(allows=allows),
        )
        event = Event(
            "http_api", "safety_controller", "tick_step", {},
        )
        assert monitor.check_route(event) is True

    @pytest.mark.security
    def test_check_domain_method(self) -> None:
        """check_domain проверяет только доменный слой."""
        allows = frozenset({
            ("safety_controller", "pseudo_ai", "regime_suggest"),
        })
        monitor = SecurityMonitor(
            route_monitor=RouteMonitor(allows=allows),
        )
        event = Event(
            "safety_controller", "pseudo_ai", "regime_suggest", {},
        )
        assert monitor.check_domain(event) is True

    @pytest.mark.security
    def test_check_parameters_method(self) -> None:
        """check_parameters проверяет только параметры."""
        allows = frozenset({
            ("http_api", "safety_controller", "start_mission"),
        })
        monitor = SecurityMonitor(
            route_monitor=RouteMonitor(allows=allows),
        )
        event = Event(
            "http_api", "safety_controller", "start_mission",
            {"target_depth_m": 50.0},
        )
        assert monitor.check_parameters(event) is True
