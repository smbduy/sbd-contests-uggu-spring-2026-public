"""Проверки безопасности АБУ — доверенная вычислительная база (ДВБ).

Модуль НЕ зависит от недоверенного кода (pseudo_ai, numpy_workflow).
Все необходимые данные передаются как параметры, а не вычисляются
внутри. Это гарантирует, что компрометация other/ не нарушит SG.

Поддерживаемые цели безопасности (SG):
- SG_ADS_Authorized_critical_commands
- SG_ADS_Controlled_operations
"""

from __future__ import annotations

from typing import Literal

RiskLevel = Literal["low", "medium", "high"]


def enforce_depth_cap(depth_m: float, max_depth_m: float) -> bool:
    """Проверка верхнего предела глубины.

    :param depth_m: текущая глубина
    :param max_depth_m: допустимый максимум
    :returns: True если можно продолжать бурение
    """
    return depth_m <= max_depth_m


def enforce_rpm_cap(rpm: float, max_rpm: float) -> bool:
    """Проверка верхнего предела оборотов.

    :param rpm: текущие обороты
    :param max_rpm: допустимый максимум
    :returns: True если обороты в пределах нормы
    """
    return rpm <= max_rpm


def should_emergency_stop(
    risk: RiskLevel,
    vibration_score: float,
    vib_threshold: float = 0.9,
) -> bool:
    """Аварийный стоп при высоком риске или аномальной вибрации.

    В отличие от заготовки, НЕ вызывает anomaly_vibration из pseudo_ai.
    Вместо этого получает уже вычисленный vibration_score как параметр.

    :param risk: уровень риска от недоверенного домена
    :param vibration_score: нормированная вибрация [0,1]
        от недоверенного домена
    :param vib_threshold: порог для аварийного стопа
    :returns: True если нужна немедленная остановка
    """
    if risk == "high":
        return True
    if vibration_score >= vib_threshold:
        return True
    return False


def check_safety_constraints(
    depth_m: float,
    max_depth_m: float,
    rpm: float,
    max_rpm: float,
    risk: RiskLevel,
    vibration_score: float,
    vib_threshold: float = 0.9,
) -> dict[str, bool | str]:
    """Комплексная проверка всех ограничений безопасности.

    :returns: словарь с результатами проверок и итоговым статусом
    """
    depth_ok = enforce_depth_cap(depth_m, max_depth_m)
    rpm_ok = enforce_rpm_cap(rpm, max_rpm)
    emergency = should_emergency_stop(risk, vibration_score, vib_threshold)

    status = "running"
    if emergency:
        status = "emergency"
    elif not depth_ok:
        status = "stopped_depth"
    elif not rpm_ok:
        status = "stopped_rpm"

    return {
        "depth_ok": depth_ok,
        "rpm_ok": rpm_ok,
        "emergency": emergency,
        "status": status,
    }
