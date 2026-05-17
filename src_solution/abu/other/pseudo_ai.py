"""Псевдо-ИИ эвристики — недоверенный код.

Вынесен за пределы ДВБ, так как не критичен для
целей безопасности (SG). Компрометация этого
модуля не должна нарушать
SG_ADS_Authorized_critical_commands и
SG_ADS_Controlled_operations, поскольку все
критичные решения принимаются в tcb.safety.
"""

from __future__ import annotations

from typing import Literal


def anomaly_vibration(samples: list[float]) -> float:
    """Оценка аномальности вибрации.

    Отклонение последнего замера от скользящего
    среднего.

    :param samples: ряд замеров (не пустой)
    :returns: значение в диапазоне [0, 1]
    """
    if not samples:
        return 1.0
    if len(samples) == 1:
        return 0.0
    window = samples[-5:]
    mean = sum(window) / len(window)
    last = window[-1]
    spread = max(abs(x - mean) for x in window) or 1e-9
    raw = abs(last - mean) / spread
    return max(0.0, min(1.0, raw))


def regime_suggest(depth_m: float, torque_nm: float) -> tuple[float, float]:
    """Эвристика рекомендуемых оборотов и подачи по глубине и моменту.

    :param depth_m: текущая глубина, м
    :param torque_nm: крутящий момент, Н·м
    :returns: (обороты_об_мин, подача_мм_об)
    """
    rpm = 120.0 + min(depth_m * 2.0, 80.0)
    if torque_nm > 5000:
        rpm *= 0.85
    feed = 0.2 + min(depth_m * 0.01, 0.15)
    return round(rpm, 1), round(feed, 3)


RiskLevel = Literal["low", "medium", "high"]


def risk_flag(vibration: float, pressure: float, depth_m: float) -> RiskLevel:
    """Пороговый классификатор риска по сенсорам.

    :param vibration: нормированная вибрация [0,1]
    :param pressure: давление, усл. ед.
    :param depth_m: глубина, м
    :returns: уровень риска
    """
    score = 0
    if vibration > 0.75:
        score += 2
    if pressure > 180.0:
        score += 2
    if depth_m > 95.0:
        score += 1
    if score >= 3:
        return "high"
    if score >= 1:
        return "medium"
    return "low"
