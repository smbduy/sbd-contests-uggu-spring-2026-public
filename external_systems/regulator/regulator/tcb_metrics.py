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
