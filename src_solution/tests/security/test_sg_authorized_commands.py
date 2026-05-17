"""Тесты SG_ADS_Authorized_critical_commands —
авторизованные критичные команды."""

from __future__ import annotations

import pytest

from src_solution.abu.tcb.safety import enforce_depth_cap, enforce_rpm_cap


@pytest.mark.security
def test_depth_cap_allows_within_limit() -> None:
    """Глубина в пределах лимита разрешена."""
    assert enforce_depth_cap(10.0, 20.0) is True


@pytest.mark.security
def test_depth_cap_rejects_over_limit() -> None:
    """Глубина сверх лимита отклонена."""
    assert enforce_depth_cap(25.0, 20.0) is False


@pytest.mark.security
def test_depth_cap_boundary() -> None:
    """Глубина точно на лимите разрешена."""
    assert enforce_depth_cap(20.0, 20.0) is True


@pytest.mark.security
def test_rpm_cap_allows_within_limit() -> None:
    """Обороты в пределах лимита разрешены."""
    assert enforce_rpm_cap(100.0, 200.0) is True


@pytest.mark.security
def test_rpm_cap_rejects_over_limit() -> None:
    """Обороты сверх лимита отклонены."""
    assert enforce_rpm_cap(300.0, 200.0) is False


@pytest.mark.security
def test_rpm_cap_boundary() -> None:
    """Обороты точно на лимите разрешены."""
    assert enforce_rpm_cap(200.0, 200.0) is True
