"""Маршрутный монитор: запрет по умолчанию
и белый список разрешённых маршрутов."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .ipc import Event


def load_allows(path: Path | None = None) -> frozenset[tuple[str, str, str]]:
    """Загрузить разрешённые маршрутные тройки
    (from, to, func) из JSON-политики.

    :param path: путь к ipc_policies.json;
        если None — рядом с этим файлом
    :returns: frozenset разрешённых троек
    """
    raw_path = path or (
        Path(__file__).resolve().parent.parent / "ipc_policies.json"
    )
    data = json.loads(raw_path.read_text(encoding="utf-8"))
    return frozenset(
        (str(item["from"]), str(item["to"]), str(item["func"]))
        for item in data.get("allows", [])
    )


class RouteMonitor:
    """Точка принятия решений: запрет по умолчанию (default deny).

    Только явно перечисленные маршруты (source, destination, operation)
    разрешены; все остальные отклоняются.
    """

    def __init__(
        self,
        allows: frozenset[tuple[str, str, str]] | None = None,
        policies_path: Path | None = None,
    ) -> None:
        """Создать маршрутный монитор.

        :param allows: явно заданный набор разрешений;
            если None — загрузить из файла
        :param policies_path: путь к файлу политик
            (используется если allows is None)
        """
        self._allows = (
            allows if allows is not None else load_allows(policies_path)
        )

    def check(self, event: Any) -> bool:
        """Вернуть True только для корректного Event с разрешённым маршрутом.

        :param event: объект для проверки
        :returns: True если маршрут разрешён политикой
        """
        if not isinstance(event, Event):
            return False
        triple = (event.source, event.destination, event.operation)
        return triple in self._allows

    @property
    def allows(self) -> frozenset[tuple[str, str, str]]:
        """Текущий набор разрешённых маршрутов (для инспекции и тестов)."""
        return self._allows
