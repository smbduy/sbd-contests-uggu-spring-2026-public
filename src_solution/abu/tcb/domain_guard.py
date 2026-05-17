"""Локальные политики выхода (egress) и входа (ingress) доменов АБУ."""

from __future__ import annotations

from .ipc import Event

RuleSet = dict[str, frozenset[tuple[str, str]]]

DEFAULT_EGRESS: RuleSet = {
    "safety_controller": frozenset({
        ("event_log", "record"),
        ("pseudo_ai", "regime_suggest"),
        ("pseudo_ai", "anomaly_vibration"),
        ("pseudo_ai", "risk_flag"),
    }),
    "http_api": frozenset({
        ("safety_controller", "start_mission"),
        ("safety_controller", "tick_step"),
        ("safety_controller", "get_status"),
        ("safety_controller", "health_check"),
        ("pseudo_ai", "ai_suggest"),
        ("event_log", "record"),
        ("event_log", "ring_snapshot"),
        ("event_log", "read_full_tail"),
    }),
    "pseudo_ai": frozenset({
        ("event_log", "record"),
    }),
    "event_log": frozenset(),
}

DEFAULT_INGRESS: RuleSet = {
    "safety_controller": frozenset({
        ("http_api", "start_mission"),
        ("http_api", "tick_step"),
        ("http_api", "get_status"),
        ("http_api", "health_check"),
    }),
    "pseudo_ai": frozenset({
        ("safety_controller", "regime_suggest"),
        ("safety_controller", "anomaly_vibration"),
        ("safety_controller", "risk_flag"),
        ("http_api", "ai_suggest"),
    }),
    "event_log": frozenset({
        ("safety_controller", "record"),
        ("http_api", "record"),
        ("http_api", "ring_snapshot"),
        ("http_api", "read_full_tail"),
        ("pseudo_ai", "record"),
    }),
    "http_api": frozenset(),
}


class DomainGuard:
    """Проверяет локальные политики отправителя и получателя.

    Egress-правила ограничивают, какие события домен может отправлять.
    Ingress-правила ограничивают, какие события домен может принимать.
    """

    def __init__(
        self,
        egress: RuleSet | None = None,
        ingress: RuleSet | None = None,
    ) -> None:
        """Создать проверяющий слой с локальными политиками.

        :param egress: правила исходящих событий по доменам
        :param ingress: правила входящих событий по доменам
        """
        self._egress = egress if egress is not None else DEFAULT_EGRESS
        self._ingress = ingress if ingress is not None else DEFAULT_INGRESS

    def check_egress(self, event: Event) -> bool:
        """Вернуть True, если отправитель может выпустить это событие."""
        allowed = self._egress.get(event.source, frozenset())
        return (event.destination, event.operation) in allowed

    def check_ingress(self, event: Event) -> bool:
        """Вернуть True, если получатель принимает это событие."""
        allowed = self._ingress.get(event.destination, frozenset())
        return (event.source, event.operation) in allowed

    def check(self, event: Event) -> bool:
        """Вернуть True, если пройдены проверки выхода и входа."""
        return self.check_egress(event) and self.check_ingress(event)
