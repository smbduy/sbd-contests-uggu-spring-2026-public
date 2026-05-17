"""Модульные тесты журнала событий."""

from __future__ import annotations

from abu.event_log import EventLevel, EventLog


def test_ring_maxlen(tmp_path) -> None:
    """Кольцо не больше 10 записей."""
    log = EventLog(tmp_path)
    for i in range(12):
        log.record(EventLevel.INFO, str(i))
    assert len(log.ring_snapshot()) == 10


def test_event_log_records_and_reads(tmp_path) -> None:
    """Запись и чтение событий в полный журнал."""
    log = EventLog(tmp_path)
    log.record(EventLevel.INFO, "test-event")
    full = log.read_full_tail()
    assert "test-event" in full


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


def test_event_log_ring_overflow(tmp_path) -> None:
    """Кольцо хранит только последние 10 событий."""
    log = EventLog(tmp_path)
    for i in range(20):
        log.record(EventLevel.INFO, f"msg-{i}")
    ring = log.ring_snapshot()
    assert len(ring) == 10
