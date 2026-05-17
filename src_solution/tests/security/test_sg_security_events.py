"""Тесты SG_ADS_Security_events_store — сохранение событий безопасности."""

from __future__ import annotations

import pytest

from src_solution.abu.tcb.event_log import EventLevel, EventLog


@pytest.mark.security
def test_event_log_ring_and_full(tmp_path) -> None:
    """События попадают в кольцо и полный журнал."""
    log = EventLog(tmp_path)
    for i in range(15):
        log.record(EventLevel.INFO, f"evt-{i}")
    ring = log.ring_snapshot()
    assert len(ring) <= 10
    full = log.read_full_tail()
    assert "evt-14" in full


@pytest.mark.security
def test_event_log_levels(tmp_path) -> None:
    """Все уровни критичности записываются."""
    log = EventLog(tmp_path)
    log.record(EventLevel.INFO, "info-msg")
    log.record(EventLevel.WARNING, "warn-msg")
    log.record(EventLevel.ERROR, "error-msg")
    log.record(EventLevel.CRITICAL, "critical-msg")
    full = log.read_full_tail()
    assert "INFO" in full
    assert "WARNING" in full
    assert "ERROR" in full
    assert "CRITICAL" in full


@pytest.mark.security
def test_event_log_ring_overflow(tmp_path) -> None:
    """Кольцо хранит только последние 10 событий."""
    log = EventLog(tmp_path)
    for i in range(20):
        log.record(EventLevel.INFO, f"msg-{i}")
    ring = log.ring_snapshot()
    assert len(ring) == 10
    assert "msg-10" in ring[0]
    assert "msg-19" in ring[-1]


@pytest.mark.security
def test_event_log_concurrent(tmp_path) -> None:
    """Потокобезопасная запись не теряет события."""
    import threading

    log = EventLog(tmp_path)
    errors: list[str] = []

    def writer(start: int) -> None:
        try:
            for i in range(50):
                log.record(EventLevel.INFO, f"thread-{start}-{i}")
        except Exception as exc:
            errors.append(str(exc))

    threads = [threading.Thread(target=writer, args=(j,)) for j in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    full = log.read_full_tail()
    assert len(full.splitlines()) == 200
