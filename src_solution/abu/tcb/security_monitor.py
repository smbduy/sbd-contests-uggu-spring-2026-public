"""Монитор безопасности АБУ: единая точка контроля междоменного взаимодействия.

Объединяет три слоя проверки:
1. RouteMonitor — маршрутные политики (default deny + whitelist)
2. DomainGuard — локальные egress/ingress правила доменов
3. ParameterGuard — семантическая валидация параметров операций

Все междоменные запросы проходят через SecurityMonitor.check().
Запрос, не прошедший хотя бы один слой, отклоняется.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .domain_guard import DomainGuard
from .parameter_guard import ParameterGuard
from .route_monitor import RouteMonitor


class SecurityMonitor:
    """Единый монитор безопасности: марштруты + домены + параметры.

    Используется как шлюз (gate) для всех IPC-взаимодействий
    между доменами АБУ. Поддерживает SG_ADS_Authorized_critical_commands
    и SG_ADS_Controlled_operations.
    """

    def __init__(
        self,
        route_monitor: RouteMonitor | None = None,
        domain_guard: DomainGuard | None = None,
        parameter_guard: ParameterGuard | None = None,
        policies_path: Path | None = None,
    ) -> None:
        """Создать монитор безопасности.

        :param route_monitor: маршрутный монитор;
            если None — создаётся из файла политик
        :param domain_guard: доменный проверяющий;
            если None — стандартные политики АБУ
        :param parameter_guard: параметрический проверяющий;
            если None — стандартные политики
        :param policies_path: путь к ipc_policies.json
            (для RouteMonitor)
        """
        self._route_monitor = route_monitor or RouteMonitor(
            policies_path=policies_path,
        )
        self._domain_guard = domain_guard or DomainGuard()
        self._parameter_guard = parameter_guard or ParameterGuard()

    def check(self, event: Any) -> bool:
        """Проверить событие через все слои безопасности.

        :param event: IPC-событие для проверки
        :returns: True если все три слоя одобрили событие
        """
        if not self._route_monitor.check(event):
            return False
        if not self._domain_guard.check(event):
            return False
        if not self._parameter_guard.check(event):
            return False
        return True

    def check_route(self, event: Any) -> bool:
        """Проверить только маршрутный слой (для диагностики и тестов)."""
        return self._route_monitor.check(event)

    def check_domain(self, event: Any) -> bool:
        """Проверить только доменный слой (для диагностики и тестов)."""
        return self._domain_guard.check(event)

    def check_parameters(self, event: Any) -> bool:
        """Проверить только параметрический слой (для диагностики и тестов)."""
        return self._parameter_guard.check(event)
