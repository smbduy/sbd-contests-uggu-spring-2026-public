"""HTTP API прототипа АБУ (решение конкурса).

Все междоменные взаимодействия проходят через SecurityMonitor.
HTTP-слой (домен http_api) не вызывает критичные операции напрямую —
запросы маршрутизируются через монитор безопасности, который проверяет:
1. Разрешён ли маршрут (RouteMonitor, default deny)
2. Допускают ли локальные политики доменов (DomainGuard)
3. Валидны ли параметры операции (ParameterGuard)
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .other.numpy_workflow import smooth_vibration_window
from .other.pseudo_ai import anomaly_vibration, regime_suggest, risk_flag
from .tcb.event_log import EventLevel, default_log
from .tcb.ipc import Event
from .tcb.safety import (
    check_safety_constraints,
)
from .tcb.security_monitor import SecurityMonitor

app = FastAPI(title="АБУ (решение конкурса)", version="1.0.0")

# Инициализация монитора безопасности из файла политик
_policies_path = Path(__file__).resolve().parent / "ipc_policies.json"
_security_monitor = SecurityMonitor(policies_path=_policies_path)


def _send_event(source: str, destination: str, operation: str,
                parameters: dict[str, Any] | None = None) -> bool:
    """Отправить IPC-событие через монитор безопасности.

    :returns: True если событие разрешено монитором
    :raises PermissionError: если событие отклонено
    """
    event = Event(
        source=source,
        destination=destination,
        operation=operation,
        parameters=parameters or {},
    )
    if not _security_monitor.check(event):
        default_log.record(
            EventLevel.ERROR,
            f"IPC_DENIED {source}->{destination}:{operation}",
        )
        raise PermissionError(
            f"запрещено политикой безопасности: "
            f"{source}->{destination}:{operation}",
        )
    return True


class MissionIn(BaseModel):
    """Входное задание на бурение."""

    target_depth_m: float = Field(gt=0, le=200)
    max_rpm: float = Field(default=300.0, gt=0)


class MissionState(BaseModel):
    """Состояние текущей миссии."""

    mission_id: str
    target_depth_m: float
    depth_m: float = 0.0
    rpm: float = 0.0
    torque_nm: float = 2000.0
    pressure: float = 120.0
    vibration_samples: list[float] = Field(default_factory=list)
    status: str = "running"


_mission: MissionState | None = None


@app.get("/api/v1/health")
def health() -> dict[str, str]:
    """Проверка работоспособности сервиса."""
    _send_event("http_api", "safety_controller", "health_check")
    _send_event("http_api", "event_log", "record", {
        "level": "INFO",
        "message": "health_check",
    })
    default_log.record(EventLevel.INFO, "health_check")
    return {"status": "ok", "service": "abu"}


@app.get("/api/v1/events/ring")
def events_ring() -> dict[str, list[str]]:
    """Снимок кольцевого буфера событий."""
    _send_event("http_api", "event_log", "ring_snapshot")
    return {"lines": default_log.ring_snapshot()}


@app.get("/api/v1/events/full")
def events_full_tail() -> dict[str, str]:
    """Хвост полного журнала событий."""
    _send_event("http_api", "event_log", "read_full_tail", {"max_lines": 500})
    return {"log": default_log.read_full_tail()}


@app.get("/api/v1/status")
def status() -> dict[str, Any]:
    """Текущий статус и телеметрия."""
    if _mission is None:
        return {"idle": True}
    m = _mission
    vib_score = (
        anomaly_vibration(m.vibration_samples)
        if m.vibration_samples else 0.0
    )
    risk_val = risk_flag(vib_score, m.pressure, m.depth_m)
    return {
        "idle": False,
        "mission_id": m.mission_id,
        "depth_m": m.depth_m,
        "rpm": m.rpm,
        "torque_nm": m.torque_nm,
        "pressure": m.pressure,
        "vibration_score": vib_score,
        "risk": risk_val,
        "mission_status": m.status,
    }


@app.post("/api/v1/missions")
def start_mission(body: MissionIn) -> dict[str, Any]:
    """Принять новое задание (упрощённо одна активная миссия)."""
    global _mission
    _send_event("http_api", "safety_controller", "start_mission", {
        "target_depth_m": body.target_depth_m,
        "max_rpm": body.max_rpm,
    })
    mid = str(uuid.uuid4())
    _mission = MissionState(
        mission_id=mid,
        target_depth_m=body.target_depth_m,
        rpm=min(150.0, body.max_rpm),
    )
    default_log.record(
        EventLevel.INFO,
        f"mission_started mission_id={mid} "
        f"target_depth_m={body.target_depth_m}",
    )
    return {"accepted": True, "mission_id": mid}


@app.get("/api/v1/missions/current")
def current_mission() -> dict[str, Any]:
    """Текущая миссия или 404."""
    if _mission is None:
        raise HTTPException(status_code=404, detail="нет активной миссии")
    return _mission.model_dump()


@app.post("/api/v1/missions/tick")
def tick_step() -> dict[str, Any]:
    """Один шаг симуляции: все критичные операции через SafetyController."""
    if _mission is None:
        raise HTTPException(status_code=400, detail="нет миссии")
    m = _mission
    if m.status != "running":
        return {"done": True, "status": m.status}

    # Проверка IPC-маршрута: http_api -> safety_controller: tick_step
    _send_event("http_api", "safety_controller", "tick_step")

    # Обновление сенсоров
    m.depth_m = round(min(m.depth_m + 0.5, m.target_depth_m), 2)
    m.vibration_samples.append(0.1 + 0.05 * (m.depth_m % 3))
    _smooth = smooth_vibration_window(m.vibration_samples)
    default_log.record(
        EventLevel.INFO,
        f"tick depth={m.depth_m} smooth_vib={_smooth:.4f}",
    )
    m.torque_nm = 2000 + m.depth_m * 30
    m.pressure = 120 + m.depth_m * 0.4

    # Запрос к недоверенному ИИ через монитор
    _send_event("safety_controller", "pseudo_ai", "regime_suggest", {
        "depth_m": m.depth_m,
        "torque_nm": m.torque_nm,
    })
    rpm_suggest, _feed = regime_suggest(m.depth_m, m.torque_nm)

    try:
        cap = float(os.environ.get("ABU_MAX_RPM", "300"))
    except ValueError:
        cap = 300.0
    m.rpm = min(rpm_suggest, cap)

    # Запрос уровня риска через монитор
    vib_score = anomaly_vibration(m.vibration_samples)
    _send_event("safety_controller", "pseudo_ai", "risk_flag", {
        "vibration": vib_score,
        "pressure": m.pressure,
        "depth_m": m.depth_m,
    })
    risk_val = risk_flag(vib_score, m.pressure, m.depth_m)

    if risk_val == "high":
        default_log.record(
            EventLevel.WARNING,
            f"risk_high depth_m={m.depth_m:.2f} rpm={m.rpm:.1f}",
        )

    # Критичные проверки безопасности (ДВБ) — НЕ зависят от pseudo_ai напрямую
    safety = check_safety_constraints(
        depth_m=m.depth_m,
        max_depth_m=m.target_depth_m + 1e-6,
        rpm=m.rpm,
        max_rpm=float(os.environ.get("ABU_MAX_RPM", "400")),
        risk=risk_val,
        vibration_score=vib_score,
    )
    m.status = safety["status"]

    if m.status == "stopped_depth":
        default_log.record(EventLevel.WARNING, "mission_stopped_depth_cap")
    elif m.status == "stopped_rpm":
        default_log.record(EventLevel.ERROR, "mission_stopped_rpm_cap")
    elif m.status == "emergency":
        default_log.record(EventLevel.CRITICAL, "emergency_stop_triggered")

    if m.depth_m >= m.target_depth_m:
        m.status = "completed"
        default_log.record(EventLevel.INFO, "mission_completed_target_depth")

    return {"mission": m.model_dump(), "risk": risk_val}


class AISuggestIn(BaseModel):
    """Вход для псевдо-ИИ подсказки."""

    depth_m: float = Field(ge=0)
    torque_nm: float = Field(ge=0)


@app.post("/api/v1/ai/suggest")
def ai_suggest(body: AISuggestIn) -> dict[str, float]:
    """Псевдо-ИИ: рекомендации режима (через монитор)."""
    _send_event("http_api", "pseudo_ai", "ai_suggest", {
        "depth_m": body.depth_m,
        "torque_nm": body.torque_nm,
    })
    rpm, feed = regime_suggest(body.depth_m, body.torque_nm)
    return {"suggested_rpm": rpm, "suggested_feed_mm_rev": feed}
