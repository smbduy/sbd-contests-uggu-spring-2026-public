"""Заглушка для проверки работоспособности ДВБ."""

from __future__ import annotations


def tcb_health() -> str:
    """Вернуть статус работоспособности ДВБ.

    :returns: строка 'ok' если ДВБ функционирует
    """
    return "ok"
