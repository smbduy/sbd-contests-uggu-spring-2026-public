"""Вычисления на numpy — недоверенный код.

numpy является «тяжёлой» зависимостью и вынесена за пределы ДВБ
в соответствии с анализом TARA (см. docs/tara_abu.md).
Размещение numpy в SBOM_OTHER снижает стоимость сертификации
и уменьшает поверхность атаки на ДВБ.
"""

from __future__ import annotations

import numpy as np


def smooth_vibration_window(samples: list[float], window: int = 5) -> float:
    """Сглаживание ряда вибраций скользящим средним (numpy).

    :param samples: замеры
    :param window: размер окна
    :returns: сглаженное значение по последнему окну
    """
    if not samples:
        return 0.0
    arr = np.array(samples[-window:], dtype=np.float64)
    return float(np.mean(arr))
