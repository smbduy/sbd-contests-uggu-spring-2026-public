"""Сквозной функциональный сценарий ЦР → АБУ (основной поток миссии).

Проверяется цепочка: регистрация установки в ЦР, создание миссии, HTTP-вызов
реального приложения АБУ (без мока ответа АБУ): httpx.AsyncClient с
ASGITransport к FastAPI-приложению ``abu.app``.
"""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

# Сохраняем до любого monkeypatch на httpx.AsyncClient (иначе рекурсия).
_HttpxAsyncClient = httpx.AsyncClient


@pytest.fixture()
def dm_client_e2e(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """ЦР с маршрутизацией POST миссии на тестовое приложение АБУ."""
    monkeypatch.setenv("CR_CERT_POLICY", "permissive")

    from abu.app import app as abu_app
    from digital_mine import main as dm

    transport = httpx.ASGITransport(app=abu_app)

    class RoutedAsyncClient:
        def __init__(self, *a, **kw):
            self._timeout = kw.get("timeout", 15.0)

        async def __aenter__(self):
            self._inner = _HttpxAsyncClient(
                transport=transport,
                base_url="http://abu.test",
                timeout=float(self._timeout),
            )
            await self._inner.__aenter__()
            return self

        async def __aexit__(self, *args):
            return await self._inner.__aexit__(*args)

        async def post(self, url: str, **kwargs):
            from urllib.parse import urlparse

            path = urlparse(url).path or "/"
            return await self._inner.post(path, **kwargs)

        async def get(self, url: str, **kwargs):
            from urllib.parse import urlparse

            path = urlparse(url).path or "/"
            return await self._inner.get(path, **kwargs)

    monkeypatch.setattr(dm.httpx, "AsyncClient", RoutedAsyncClient)
    return TestClient(dm.app)


def test_e2e_dm_registers_rig_and_mission_reaches_abu(dm_client_e2e: TestClient) -> None:
    """Регистрация буровой → миссия → АБУ принимает задание и возвращает mission_id."""
    r1 = dm_client_e2e.post(
        "/api/v1/rigs",
        json={
            "rig_id": "e2e-rig-1",
            "abu_base_url": "http://127.0.0.1:8081",
            "certificate_id": None,
        },
    )
    assert r1.status_code == 200, r1.text

    r2 = dm_client_e2e.post(
        "/api/v1/missions",
        json={"rig_id": "e2e-rig-1", "target_depth_m": 12.0, "max_rpm": 180.0},
    )
    assert r2.status_code == 200, r2.text
    body = r2.json()
    abu_resp = body.get("abu_response") or {}
    assert abu_resp.get("accepted") is True
    assert "mission_id" in abu_resp and abu_resp["mission_id"]
