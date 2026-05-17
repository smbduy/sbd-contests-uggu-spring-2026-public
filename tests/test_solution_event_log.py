"""Тесты src_solution.abu.tcb.event_log — импорт из src_solution + event_log (C15)."""

from __future__ import annotations

import pytest

from src_solution.abu.tcb.event_log import EventLevel, EventLog


def test_event_log_records_and_reads(tmp_path) -> None:
    """Запись и чтение событий."""
    log = EventLog(tmp_path)
    log.record(EventLevel.INFO, "test-event")
    assert "test-event" in log.read_full_tail()


def test_event_log_ring_size_property(tmp_path) -> None:
    """Свойство ring_size возвращает текущий размер."""
    log = EventLog(tmp_path)
    assert log.ring_size == 0
    log.record(EventLevel.INFO, "evt1")
    assert log.ring_size == 1


def test_event_log_max_ring_size(tmp_path) -> None:
    """Свойство max_ring_size возвращает 10."""
    log = EventLog(tmp_path)
    assert log.max_ring_size == 10


def test_event_log_full_tail_empty(tmp_path) -> None:
    """Пустой журнал возвращает пустую строку."""
    log = EventLog(tmp_path)
    assert log.read_full_tail() == ""
