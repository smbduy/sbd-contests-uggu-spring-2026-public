"""Метрики исходного кода доверенной базы (ДВБ): строки и цикломатическая сложность."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable


def iter_python_files(package_root: Path) -> list[Path]:
    """Все *.py под каталогом пакета, без __pycache__."""
    if not package_root.is_dir():
        return []
    out: list[Path] = []
    for p in sorted(package_root.rglob("*.py")):
        if "__pycache__" in p.parts:
            continue
        out.append(p)
    return out


def count_physical_loc(paths: Iterable[Path]) -> int:
    """Физическое число строк в перечисленных файлах."""
    total = 0
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        total += len(text.splitlines())
    return total


def _cyclomatic_of_function(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    """
    Цикломатическая сложность одной функции (Маккейб): база 1 + точки ветвления.

    Вложенные определения функций не учитываются внутри внешней (они считаются отдельно).
    """

    class V(ast.NodeVisitor):
        def __init__(self) -> None:
            self.score = 1

        def visit_If(self, n: ast.If) -> None:
            self.score += 1
            self.generic_visit(n)

        def visit_While(self, n: ast.While) -> None:
            self.score += 1
            self.generic_visit(n)

        def visit_For(self, n: ast.For) -> None:
            self.score += 1
            self.generic_visit(n)

        def visit_AsyncFor(self, n: ast.AsyncFor) -> None:
            self.score += 1
            self.generic_visit(n)

        def visit_ExceptHandler(self, n: ast.ExceptHandler) -> None:
            self.score += 1
            self.generic_visit(n)

        def visit_With(self, n: ast.With) -> None:
            self.score += 1
            self.generic_visit(n)

        def visit_Assert(self, n: ast.Assert) -> None:
            self.score += 1
            self.generic_visit(n)

        def visit_BoolOp(self, n: ast.BoolOp) -> None:
            self.score += len(n.values) - 1
            self.generic_visit(n)

        def visit_FunctionDef(self, n: ast.FunctionDef) -> None:
            return  # вложенные функции — отдельные сущности

        def visit_AsyncFunctionDef(self, n: ast.AsyncFunctionDef) -> None:
            return

    v = V()
    for stmt in node.body:
        v.visit(stmt)
    return v.score


def sum_cyclomatic_complexity(paths: Iterable[Path]) -> int:
    """
    Сумма цикломатических сложностей по всем функциям и методам в файлах пакета.
    """
    total = 0
    for path in paths:
        try:
            src = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            tree = ast.parse(src, filename=str(path))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                total += _cyclomatic_of_function(node)
    return total


def compute_tcb_source_metrics(abu_package_root: Path) -> tuple[int, int]:
    """
    Возвращает (число строк, суммарная цикломатическая сложность) для каталога пакета АБУ (например source/abu).
    """
    py_files = iter_python_files(abu_package_root)
    loc = count_physical_loc(py_files)
    cc = sum_cyclomatic_complexity(py_files)
    return loc, cc


def partition_tcb_into_domains(
    tcb_root: Path,
    spec: dict,
) -> tuple[list[tuple[str, int, int]], list[str]]:
    """Разбивает файлы ДВБ на домены по спецификации и остаток.

    :param tcb_root: каталог с исходниками ДВБ
    :param spec: словарь с ключом "domains", содержащий список
        {"id": str, "globs": [str]}
    :returns: (список_доменов, список_предупреждений)
        Каждый домен — (domain_id, loc, cyclomatic_complexity)
    """
    import fnmatch

    all_py = iter_python_files(tcb_root)
    if not all_py:
        return [("_residual", 0, 0)], ["пустой каталог ДВБ"]

    domains_spec = spec.get("domains") or []
    assigned: dict[str, list[Path]] = {}
    for d in domains_spec:
        did = d.get("id", "_unknown")
        globs = d.get("globs") or []
        matched: list[Path] = []
        for g in globs:
            for p in all_py:
                if fnmatch.fnmatch(p.name, g) and p not in matched:
                    matched.append(p)
        assigned[did] = matched

    # Остаток
    used: set[Path] = set()
    for paths in assigned.values():
        used.update(paths)
    residual = [p for p in all_py if p not in used]
    if residual:
        assigned["_residual"] = residual

    warnings: list[str] = []
    rows: list[tuple[str, int, int]] = []
    for did, paths in assigned.items():
        if not paths:
            rows.append((did, 0, 0))
            continue
        loc = count_physical_loc(paths)
        cc = sum_cyclomatic_complexity(paths)
        rows.append((did, loc, cc))

    return rows, warnings
