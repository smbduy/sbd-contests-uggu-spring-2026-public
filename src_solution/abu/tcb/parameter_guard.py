"""Политики параметров операций для IPC-событий АБУ."""

from __future__ import annotations

from collections.abc import Callable

from .ipc import Event

ParameterPolicy = Callable[[Event], bool]


class ParameterGuard:
    """Проверяет семантику полезной нагрузки после маршрутных проверок.

    Каждая операция имеет свою политику валидации параметров.
    Если операция неизвестна — событие отклоняется (default deny).
    """

    def __init__(
        self,
        policies: dict[str, ParameterPolicy] | None = None,
    ) -> None:
        """Создать проверяющий слой с параметрическими политиками.

        :param policies: словарь {operation: validator};
            если None — стандартные политики АБУ
        """
        self._policies = policies if policies is not None else {
            "start_mission": self._check_start_mission,
            "tick_step": self._check_tick_step,
            "get_status": self._check_no_params,
            "health_check": self._check_no_params,
            "record": self._check_record,
            "ring_snapshot": self._check_no_params,
            "read_full_tail": self._check_read_full_tail,
            "regime_suggest": self._check_regime_suggest,
            "anomaly_vibration": self._check_anomaly_vibration,
            "risk_flag": self._check_risk_flag,
            "ai_suggest": self._check_ai_suggest,
        }

    def check(self, event: Event) -> bool:
        """Вернуть True, если параметры события соответствуют политике.

        :param event: IPC-событие для проверки
        :returns: True если параметры валидны
        """
        policy = self._policies.get(event.operation)
        return bool(policy and policy(event))

    @staticmethod
    def _check_start_mission(event: Event) -> bool:
        """Валидация параметров запуска миссии."""
        p = event.parameters
        target = p.get("target_depth_m")
        max_rpm = p.get("max_rpm")
        if not isinstance(target, (int, float)) or target <= 0 or target > 200:
            return False
        if max_rpm is not None and (
            not isinstance(max_rpm, (int, float)) or max_rpm <= 0
        ):
            return False
        return True

    @staticmethod
    def _check_tick_step(event: Event) -> bool:
        """Тик не требует обязательных параметров (состояние внутри домена)."""
        return True

    @staticmethod
    def _check_no_params(event: Event) -> bool:
        """Операции без обязательных параметров."""
        return True

    @staticmethod
    def _check_record(event: Event) -> bool:
        """Валидация записи в журнал событий."""
        p = event.parameters
        level = p.get("level", "INFO")
        if level not in {"INFO", "WARNING", "ERROR", "CRITICAL"}:
            return False
        message = p.get("message")
        if not isinstance(message, str) or not 1 <= len(message) <= 500:
            return False
        return True

    @staticmethod
    def _check_read_full_tail(event: Event) -> bool:
        """Валидация запроса хвоста журнала."""
        max_lines = event.parameters.get("max_lines", 500)
        return isinstance(max_lines, int) and max_lines > 0

    @staticmethod
    def _check_regime_suggest(event: Event) -> bool:
        """Валидация запроса режима бурения."""
        p = event.parameters
        depth = p.get("depth_m")
        torque = p.get("torque_nm")
        if not isinstance(depth, (int, float)) or depth < 0:
            return False
        if not isinstance(torque, (int, float)) or torque < 0:
            return False
        return True

    @staticmethod
    def _check_anomaly_vibration(event: Event) -> bool:
        """Валидация запроса оценки аномалии вибрации."""
        p = event.parameters
        samples = p.get("samples")
        return isinstance(samples, list)

    @staticmethod
    def _check_risk_flag(event: Event) -> bool:
        """Валидация запроса уровня риска."""
        p = event.parameters
        vib = p.get("vibration")
        press = p.get("pressure")
        depth = p.get("depth_m")
        if not isinstance(vib, (int, float)):
            return False
        if not isinstance(press, (int, float)):
            return False
        if not isinstance(depth, (int, float)):
            return False
        return True

    @staticmethod
    def _check_ai_suggest(event: Event) -> bool:
        """Валидация запроса ИИ-подсказки."""
        p = event.parameters
        depth = p.get("depth_m")
        torque = p.get("torque_nm")
        if not isinstance(depth, (int, float)) or depth < 0:
            return False
        if not isinstance(torque, (int, float)) or torque < 0:
            return False
        return True
