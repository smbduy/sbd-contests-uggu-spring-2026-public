"""Песочница: изолированные зависимости (pip --target) и pytest с покрытием по коду АБУ."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PytestCovResult:
    """Результат прогона pytest с покрытием."""

    ok: bool
    coverage_total: float
    coverage_tcb: float
    coverage_other: float
    log: str


def run_pytest_with_coverage(
    source_dir: Path,
    tests_subdir: str = "tests",
    cov_package: str = "abu",
    fail_under: float = 80.0,
    extra_pytest_args: list[str] | None = None,
) -> tuple[bool, float, str]:
    """
    Ставит зависимости во временный каталог (pip install -t), запускает pytest --cov.

    Не использует системный site-packages; пригодно для сред без полноценного python3-venv.

    :param source_dir: каталог с кодом АБУ (содержит abu/, tests/, requirements.txt)
    :param tests_subdir: подкаталог с тестами относительно source_dir
    :param cov_package: пакет для измерения покрытия
    :param fail_under: минимальный процент покрытия
    :returns: (успех, процент_покрытия_или_0, объединённый лог)
    """
    req = source_dir / "requirements.txt"
    if not req.is_file():
        return False, 0.0, "нет requirements.txt в пакете"

    tmp = Path(tempfile.mkdtemp(prefix="reg_sandbox_"))
    lib = tmp / "pylib"
    lib.mkdir(parents=True)
    try:
        inst = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "-q",
                "-r",
                str(req),
                "-t",
                str(lib),
                "pytest",
                "pytest-cov",
            ],
            capture_output=True,
            text=True,
        )
        if inst.returncode != 0:
            return False, 0.0, inst.stdout + inst.stderr

        tests_path = source_dir / tests_subdir
        env = os.environ.copy()
        sep = os.pathsep
        env["PYTHONPATH"] = sep.join([str(source_dir), str(lib)])

        cov_threshold = os.environ.get("REGULATOR_COV_FAIL_UNDER", str(fail_under))
        cmd = [
            sys.executable,
            "-m",
            "pytest",
            str(tests_path),
            "-q",
            f"--cov={cov_package}",
            "--cov-report=term-missing",
            f"--cov-fail-under={cov_threshold}",
        ]
        if extra_pytest_args:
            cmd.extend(extra_pytest_args)
        pr = subprocess.run(
            cmd,
            cwd=str(source_dir),
            capture_output=True,
            text=True,
            env=env,
        )
        log = pr.stdout + "\n" + pr.stderr
        coverage_pct = _parse_coverage_percent(log)
        ok = pr.returncode == 0
        return ok, coverage_pct, log
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _parse_coverage_percent(log: str) -> float:
    """Извлекает TOTAL coverage из вывода pytest-cov."""
    for line in log.splitlines():
        if "TOTAL" in line and "%" in line:
            parts = line.split()
            for p in parts:
                if p.endswith("%"):
                    try:
                        return float(p.rstrip("%"))
                    except ValueError:
                        continue
    return 0.0


def run_security_tests_coverage(
    source_dir: Path,
    cov_package: str = "abu",
    fail_under: float | None = None,
) -> tuple[bool, float, str]:
    """
    Запускает только tests/security с порогом покрытия (по умолчанию REGULATOR_SECURITY_COV_FAIL_UNDER=70).

    Если каталога tests/security нет — возвращает успех без прогона.
    """
    sec = source_dir / "tests" / "security"
    if not sec.is_dir():
        return True, 100.0, "tests/security отсутствует, пропуск"

    fu = fail_under
    if fu is None:
        fu = float(os.environ.get("REGULATOR_SECURITY_COV_FAIL_UNDER", "70"))

    return run_pytest_with_coverage(
        source_dir,
        tests_subdir="tests/security",
        cov_package=cov_package,
        fail_under=fu,
    )


def _aggregate_tcb_other_percent(
    log: str,
    flat_legacy: bool = False,
) -> tuple[float, float]:
    """Разбивает покрытие из лога pytest-cov на ДВБ и прочее.

    :param log: вывод pytest --cov-report=term-missing
    :param flat_legacy: если True — всё считается как ДВБ
        (для старых неразделённых макетов)
    :returns: (coverage_tcb_percent, coverage_other_percent)
    """
    tcb_lines: list[tuple[int, int]] = []  # (covered, total)
    other_lines: list[tuple[int, int]] = []

    for line in log.splitlines():
        stripped = line.strip()
        # Совпадает с форматом pytest-cov: путь  stmts  miss  cover%
        m = re.match(
            r"^(abu\S+\.py)\s+(\d+)\s+(\d+)\s+(\d+)%",
            stripped,
        )
        if not m:
            continue
        path, stmts_str, miss_str = m.group(1), m.group(2), m.group(3)
        stmts = int(stmts_str)
        miss = int(miss_str)
        covered = stmts - miss

        if flat_legacy:
            tcb_lines.append((covered, stmts))
        elif path.startswith("abu/tcb/"):
            tcb_lines.append((covered, stmts))
        else:
            other_lines.append((covered, stmts))

    def _pct(items: list[tuple[int, int]]) -> float:
        if not items:
            return 100.0
        total_covered = sum(c for c, _ in items)
        total_stmts = sum(t for _, t in items)
        if total_stmts == 0:
            return 100.0
        return 100.0 * total_covered / total_stmts

    return _pct(tcb_lines), _pct(other_lines)
