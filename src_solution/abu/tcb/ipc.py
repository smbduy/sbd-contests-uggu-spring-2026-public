"""Канонический формат IPC-события для доменов АБУ.

Реализует шаблон request/response: домен-отправитель формирует
запрос (Event), SecurityMonitor проверяет его, и результат
доставляется домену-получателю как ответ на запрос.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Event:
    """IPC-запрос между доменами АБУ (request/response).

    Атрибуты:
        source: идентификатор домена-отправителя (request origin)
        destination: идентификатор домена-получателя (response target)
        operation: имя запрашиваемой операции
        parameters: словарь параметров операции
    """

    source: str
    destination: str
    operation: str
    parameters: dict[str, Any]
