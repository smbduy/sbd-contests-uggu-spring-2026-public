"""Журнал событий АБУ — доверенная вычислительная база (ДВБ).

Поддерживает SG_ADS_Security_events_store: при любых обстоятельствах
сохраняются события безопасности.

Реализует кольцевой буфер фиксированного размера и полный журнал в файле.
Потокобезопасен через threading.Lock.
"""

from __future__ import annotations

import threading
from collections import deque
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path


class EventLevel(str, Enum):
    """Уровень критичности события."""

    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


_RING_SIZE = 10


class EventLog:
    """Кольцевой буфер и полный журнал событий АБУ.

    :param log_dir: каталог для abu_events_full.log и abu_events_ring.txt
    """

    def __init__(self, log_dir: Path | None = None) -> None:
        self._dir = log_dir or Path.cwd() / "var" / "abu_logs"
        self._dir.mkdir(parents=True, exist_ok=True)
        self._full_path = self._dir / "abu_events_full.log"
        self._ring_path = self._dir / "abu_events_ring.txt"
        self._ring: deque[str] = deque(maxlen=_RING_SIZE)
        self._lock = threading.Lock()

    def record(self, level: EventLevel, message: str) -> None:
        """Записать событие в кольцевой буфер и полный журнал.

        :param level: уровень критичности
        :param message: текст события
        """
        ts = datetime.now(timezone.utc).isoformat()
        line = f"{ts}\t{level.value}\t{message}\n"
        with self._lock:
            self._ring.append(line.strip())
            with self._full_path.open("a", encoding="utf-8") as fh:
                fh.write(line)
            self._ring_path.write_text(
                "".join(f"{x}\n" for x in self._ring),
                encoding="utf-8",
            )

    def ring_snapshot(self) -> list[str]:
        """Текущее содержимое кольца (от старых к новым).

        :returns: список строк событий в пределах окна
        """
        with self._lock:
            return list(self._ring)

    def read_full_tail(self, max_lines: int = 500) -> str:
        """Хвост полного журнала.

        :param max_lines: максимальное число строк
        :returns: текст последних строк журнала
        """
        if not self._full_path.is_file():
            return ""
        lines = self._full_path.read_text(encoding="utf-8").splitlines()
        return "\n".join(lines[-max_lines:])

    @property
    def ring_size(self) -> int:
        """Текущий размер кольцевого буфера."""
        with self._lock:
            return len(self._ring)

    @property
    def max_ring_size(self) -> int:
        """Максимальный размер кольцевого буфера."""
        return _RING_SIZE


# Глобальный журнал процесса
default_log = EventLog()
