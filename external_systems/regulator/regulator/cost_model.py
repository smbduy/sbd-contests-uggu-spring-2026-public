"""Оценка стоимости сертификации: ДВБ стимулирует малые графы связей, а не «массу» компонентов."""

from __future__ import annotations

import json
import re
from pathlib import Path

# Вклад «прочего» SBOM в итоговую стоимость (понижающий коэффициент).
SBOM_OTHER_COST_DIVISOR = 100

# Крупные зависимости в ДВБ: при наличии в SBOM_TCB или requirements — множитель к стоимости.
HEAVY_DV_B_DEPS = ("numpy",)
HEAVY_DEP_COST_MULTIPLIER = 2.0

# Дополнительный вклад исходного кода ДВБ (пакет abu в сертификационном архиве): строки и цикломатика.
LOC_COST_PER_LINE = 0.15
CC_COST_PER_POINT = 0.8

# SBOM_TCB: число компонентов N не входит в стоимость — допускается дробление ДВБ на много малых доменов.
# Штрафуются рёбра графа зависимостей E (связи между компонентами/доменами).
TCB_SBOM_BASE = 1000.0
TCB_EDGE_LINEAR = 25.0
TCB_EDGE_QUADRATIC = 1.8

# SBOM_OTHER (до деления на divisor): без штрафа за число компонентов, только база и рёбра.
OTHER_SBOM_BASE = 500.0
OTHER_EDGE_LINEAR = 0.5

# Междоменные IPC-рёбра: учёт доверенных и недоверенных границ.
DOMAIN_IPC_EDGE_UNIT = 1.0
DOMAIN_IPC_TRUSTED_VS_UNTRUSTED_FACTOR = 2.0


def estimate_tcb_sbom_cost(edges: int) -> float:
    """
    Вклад CycloneDX SBOM_TCB в условных единицах.

    Формула не зависит от числа компонентов (доменов безопасности) — только от числа рёбер E
    (связей между компонентами в графе зависимостей), линейно и квадратично, чтобы стимулировать
    слабосвязанные малые домены безопасности.

    :param edges: число рёбер зависимостей в SBOM_TCB
    """
    e = float(max(0, edges))
    return TCB_SBOM_BASE + TCB_EDGE_LINEAR * e + TCB_EDGE_QUADRATIC * e * e


def estimate_other_sbom_cost(edges: int) -> float:
    """
    Вклад CycloneDX SBOM_OTHER до деления на divisor.

    Число компонентов не входит — только рёбра прочего графа (по смыслу согласовано с TCB).
    """
    e = float(max(0, edges))
    return OTHER_SBOM_BASE + OTHER_EDGE_LINEAR * e


def tcb_source_cost_addon(tcb_loc: int, tcb_cyclomatic_sum: int) -> float:
    """
    Дополнительная стоимость по метрикам исходников ДВБ (строки и суммарная цикломатика функций).

    :param tcb_loc: физическое число строк *.py в пакете abu
    :param tcb_cyclomatic_sum: сумма цикломатических сложностей по всем функциям/методам
    """
    return float(LOC_COST_PER_LINE) * float(tcb_loc) + float(CC_COST_PER_POINT) * float(
        tcb_cyclomatic_sum
    )


def estimate_domain_ipc_communication_cost(
    ipc_untrusted_boundary_edges: int,
    ipc_trusted_boundary_edges: int,
) -> float:
    """Стоимость междоменного IPC: недоверенные и доверенные рёбра.

    Доверенное ребро стоит DOMAIN_IPC_TRUSTED_VS_UNTRUSTED_FACTOR раз дороже
    недоверенного (больше проверок, выше требования к верификации).

    :param ipc_untrusted_boundary_edges: число недоверенных IPC-рёбер
    :param ipc_trusted_boundary_edges: число доверенных IPC-рёбер
    """
    return (
        float(ipc_untrusted_boundary_edges) * DOMAIN_IPC_EDGE_UNIT
        + float(ipc_trusted_boundary_edges)
        * DOMAIN_IPC_EDGE_UNIT
        * DOMAIN_IPC_TRUSTED_VS_UNTRUSTED_FACTOR
    )


def total_estimated_cost(
    n_tcb: int,
    n_tcb_edges: int,
    n_other: int,
    n_other_edges: int,
    *,
    tcb_loc: int = 0,
    tcb_cyclomatic_sum: int = 0,
    ipc_untrusted_boundary_edges: int = 0,
    ipc_trusted_boundary_edges: int = 0,
) -> float:
    """
    Итоговая стоимость: SBOM_TCB (только по рёбрам E), исходники abu, SBOM_OTHER / divisor,
    междоменный IPC.

    Параметры n_tcb и n_other сохраняются в сигнатуре для совместимости с парсером SBOM и
    отладки; в формулу стоимости не входят.
    """
    _ = n_tcb, n_other  # метрики компонентов не штрафуются
    cost_tcb = estimate_tcb_sbom_cost(n_tcb_edges) + tcb_source_cost_addon(tcb_loc, tcb_cyclomatic_sum)
    cost_other = estimate_other_sbom_cost(n_other_edges)
    cost_ipc = estimate_domain_ipc_communication_cost(
        ipc_untrusted_boundary_edges,
        ipc_trusted_boundary_edges,
    )
    return cost_tcb + cost_other / float(SBOM_OTHER_COST_DIVISOR) + cost_ipc


def tcb_partition_verification_addon(
    domains: list[tuple[str, int, int]],
    incoming_allowances: dict[str, int],
) -> tuple[float, list[float]]:
    """Стоимость верификации разбиения ДВБ на домены.

    Выпуклая по LOC на домен: стимулирует разбиение на малые домены.
    Полином по входящим IPC-разрешениям R_d.

    :param domains: список (domain_id, loc, cyclomatic_complexity)
    :param incoming_allowances: словарь {domain_id: R_d} —
        число разрешённых входящих междоменных IPC
    :returns: (суммарная_стоимость, список_стоимостей_по_доменам)
    """
    per_domain: list[float] = []
    for domain_id, loc, cc in domains:
        r = incoming_allowances.get(domain_id, 0)
        # Выпуклый вклад по LOC (квадратичный штраф за большие домены)
        loc_cost = LOC_COST_PER_LINE * loc * (1.0 + loc / 1000.0)
        cc_cost = CC_COST_PER_POINT * cc
        # Полином по входящим IPC: R + 0.1 * R^2
        r_cost = float(r) + 0.1 * float(r) * float(r)
        per_domain.append(loc_cost + cc_cost + r_cost)
    return sum(per_domain), per_domain


def sbom_has_heavy_dep(sbom_path: Path, heavy_names: tuple[str, ...] = HEAVY_DV_B_DEPS) -> bool:
    """Проверяет, есть ли в CycloneDX компонент с именем из heavy_names (без учёта регистра)."""
    if not sbom_path.is_file():
        return False
    data = json.loads(sbom_path.read_text(encoding="utf-8"))
    components = data.get("components") or []
    lowered = {n.lower() for n in heavy_names}
    for comp in components:
        name = (comp.get("name") or "").lower()
        if name in lowered:
            return True
    return False


def requirements_has_heavy_dep(req_path: Path, heavy_names: tuple[str, ...] = HEAVY_DV_B_DEPS) -> bool:
    """Проверяет requirements.txt на упоминание пакета (строка начинается с имени)."""
    if not req_path.is_file():
        return False
    text = req_path.read_text(encoding="utf-8", errors="replace")
    lowered = {n.lower() for n in heavy_names}
    for line in text.splitlines():
        line = line.strip().split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        pkg = re.split(r"[<>=!~\[\s;]", line, maxsplit=1)[0].strip().lower()
        if pkg in lowered:
            return True
    return False


def apply_heavy_dep_multiplier(
    base_cost: float,
    sbom_tcb_path: Path | None,
    requirements_path: Path | None,
) -> float:
    """Удваивает стоимость, если numpy и т.п. присутствуют в ДВБ (SBOM_TCB или requirements)."""
    if sbom_tcb_path and sbom_has_heavy_dep(sbom_tcb_path):
        return base_cost * HEAVY_DEP_COST_MULTIPLIER
    if requirements_path and requirements_has_heavy_dep(requirements_path):
        return base_cost * HEAVY_DEP_COST_MULTIPLIER
    return base_cost
