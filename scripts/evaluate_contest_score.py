#!/usr/bin/env python3
"""
Оценка по 22 критериям (макс. 3 балла каждый; номинальная сумма RAW_MAX).
Оцениваются в первую очередь изменения конкурсанта (src_solution/, тесты, отчётные артефакты).

Итог для отчёта: нормализация в диапазон [10, 20]:
    display = 10 + (raw / RAW_MAX) * 10

Запуск: из корня репозитория, после `make install`.
  pipenv run python scripts/evaluate_contest_score.py

Опции:
  --no-pytest   не запускать pytest (использовать только проверки артефактов)
  --json        вывести JSON со списком критериев

C09: flake8 по src_solution/ (при наличии .py).
C14: numpy в SBOM решения (SBOM_TCB vs SBOM_OTHER), макс. 3.
C16: покрытие src_solution.abu.tcb из pytest с --cov=src_solution.abu.tcb.
C17: эвристика полноты docs/solution.md.
C18–C19: эвристики по каталогу src_solution/ и тестам (без изменения src_starting_point).
C20–C22: экспертные; в скрипте 0, жюри.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from pathlib import Path

# Все 22 критерия с максимумом 3 (включая C14)
RAW_MAX = 66.0

ROOT = Path(__file__).resolve().parents[1]

E2E_TEST_PATH = ROOT / "tests" / "test_e2e_abu_dm_scenario.py"
SOLUTION_MD_PATH = ROOT / "docs" / "solution.md"


def _src_solution_snapshot() -> tuple[list[Path], str]:
    """Возвращает список .py под src_solution/ и объединённый текст (для эвристик)."""
    sol = ROOT / "src_solution"
    if not sol.is_dir():
        return [], ""
    try:
        py_files = [p for p in sol.rglob("*.py") if p.is_file()]
    except OSError:
        return [], ""
    if not py_files:
        return [], ""
    chunks: list[str] = []
    for p in py_files:
        try:
            chunks.append(p.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            pass
    return py_files, "\n".join(chunks)


def _exists(rel: str) -> bool:
    return (ROOT / rel).is_file() or (ROOT / rel).is_dir()


def _security_test_files() -> list[Path]:
    out: list[Path] = []
    for base in (ROOT / "tests" / "security", ROOT / "src_starting_point" / "tests" / "security"):
        if base.is_dir():
            out.extend(p for p in base.glob("test_*.py") if p.is_file())
    return out


def _parse_python_file(path: Path) -> ast.AST | None:
    try:
        return ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError):
        return None


def _imports_src_solution(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("src_solution"):
                    return True
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.startswith("src_solution"):
                return True
    return False


def _test_files_importing_src_solution() -> list[Path]:
    found: list[Path] = []
    tests_root = ROOT / "tests"
    if not tests_root.is_dir():
        return found
    for tp in tests_root.rglob("*.py"):
        if not tp.is_file():
            continue
        tree = _parse_python_file(tp)
        if tree and _imports_src_solution(tree):
            found.append(tp)
    return found


def _test_files_importing_event_log_and_src_solution() -> list[Path]:
    found: list[Path] = []
    tests_root = ROOT / "tests"
    if not tests_root.is_dir():
        return found
    for tp in tests_root.rglob("*.py"):
        if not tp.is_file():
            continue
        tree = _parse_python_file(tp)
        if not tree:
            continue
        has_sol = _imports_src_solution(tree)
        has_el = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if "event_log" in a.name:
                        has_el = True
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if "event_log" in mod:
                    has_el = True
                for a in node.names:
                    if "event_log" in (a.name or ""):
                        has_el = True
        if has_sol and has_el:
            found.append(tp)
    return found


def _count_test_functions(path: Path) -> int:
    tree = _parse_python_file(path)
    if not tree:
        return 0
    n = 0
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
            n += 1
    return n


def _pytest_ini_has_security_marker() -> bool:
    p = ROOT / "pytest.ini"
    if not p.is_file():
        return False
    txt = p.read_text(encoding="utf-8", errors="replace")
    return "security" in txt.lower()


def _security_marker_used_in_tests() -> int:
    """Число тестовых файлов с @pytest.mark.security."""
    n = 0
    for base in (ROOT / "tests", ROOT / "src_starting_point" / "tests"):
        if not base.is_dir():
            continue
        for tp in base.rglob("*.py"):
            if not tp.is_file():
                continue
            try:
                t = tp.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "pytest.mark.security" in t or "@pytest.mark.security" in t:
                n += 1
    return n


def score_c18_c19_solution(py_files: list[Path], blob: str) -> tuple[float, float, str, str]:
    """C18/C19: целые уровни 0–3 по признакам в коде и тестах (AST для тестов с src_solution)."""
    if not py_files and not blob.strip():
        return 0.0, 0.0, "src_solution отсутствует или пуст", "src_solution отсутствует или пуст"

    lower = blob.lower()
    path_blob = " ".join(str(p.relative_to(ROOT)).lower() for p in py_files)

    has_monitor_name = "security_monitor" in path_blob or "security_monitor" in lower
    has_policies_path = "policies" in path_blob or any(part == "policies" for p in py_files for part in p.parts)
    has_policies_code = "policies" in lower or "policy" in lower

    test_ast_hits = 0
    for tp in _test_files_importing_src_solution():
        tree = _parse_python_file(tp)
        if not tree:
            continue
        t = tp.read_text(encoding="utf-8", errors="replace").lower()
        if "security_monitor" in t or "policies" in t:
            test_ast_hits += 1

    c18_note_parts: list[str] = []
    if has_monitor_name:
        c18_note_parts.append("monitor")
    if has_policies_path or has_policies_code:
        c18_note_parts.append("policies")
    if test_ast_hits:
        c18_note_parts.append(f"тесты≈{test_ast_hits}")

    if has_monitor_name and (has_policies_path or has_policies_code) and test_ast_hits >= 2:
        c18 = 3.0
    elif has_monitor_name and (has_policies_path or has_policies_code) and test_ast_hits >= 1:
        c18 = 2.0
    elif has_monitor_name and (has_policies_path or has_policies_code):
        c18 = 1.0
    elif has_monitor_name or has_policies_path or has_policies_code:
        c18 = 1.0
    else:
        c18 = 0.0
    c18_note = ", ".join(c18_note_parts) if c18_note_parts else "нет признаков"

    has_domain = "domain" in path_blob or "domains" in path_blob or "domain" in lower
    has_monitor_word = "monitor" in lower or "mediator" in lower
    has_req_resp = "request" in lower and "response" in lower

    c19_note_parts: list[str] = []
    if has_domain:
        c19_note_parts.append("domains")
    if has_monitor_word:
        c19_note_parts.append("monitor")
    if has_req_resp:
        c19_note_parts.append("request/response")

    sigs = sum([has_domain, has_monitor_word, has_req_resp])
    if sigs >= 3:
        c19 = 3.0
    elif sigs == 2:
        c19 = 2.0
    elif sigs == 1:
        c19 = 1.0
    else:
        c19 = 0.0
    c19_note = ", ".join(c19_note_parts) if c19_note_parts else "нет признаков"

    return c18, c19, c18_note, c19_note


def _parse_total_coverage_percent(log: str) -> float | None:
    """Извлекает TOTAL %% из вывода pytest-cov."""
    for line in log.splitlines():
        if line.strip().startswith("TOTAL"):
            parts = line.split()
            for p in parts:
                if p.endswith("%"):
                    try:
                        return float(p.rstrip("%"))
                    except ValueError:
                        continue
    return None


def run_pytest_with_tcb_coverage() -> tuple[int, float | None]:
    """Прогон pytest с измерением покрытия ДВБ решения: src_solution.abu.tcb."""
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "src_starting_point/tests",
            "tests",
            "--cov=src_solution.abu.tcb",
            "--cov-report=term-missing",
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=600,
    )
    log = (proc.stdout or "") + (proc.stderr or "")
    pct = _parse_total_coverage_percent(log)
    return proc.returncode, pct


def score_c16_tcb_coverage(pct: float | None, pytest_skipped: bool) -> tuple[float, str]:
    """Покрытие подкаталога src_solution/abu/tcb (ДВБ решения) тестами: пороги по TOTAL."""
    if pytest_skipped:
        return 0.0, "пропуск pytest"
    if pct is None:
        return 0.0, "нет данных coverage"
    if pct >= 80.0:
        return 3.0, f"{pct:.1f}% (≥80%)"
    if pct >= 60.0:
        return 2.0, f"{pct:.1f}% (60–79%)"
    if pct >= 40.0:
        return 1.0, f"{pct:.1f}% (40–59%)"
    return 0.0, f"{pct:.1f}% (<40%)"


def run_flake8_src_solution() -> tuple[int | None, str]:
    """flake8 по src_solution. Возвращает (число строк с замечаниями, None) или (None, причина)."""
    sol = ROOT / "src_solution"
    if not sol.is_dir():
        return None, "нет каталога"
    py_files = [p for p in sol.rglob("*.py") if p.is_file()]
    if not py_files:
        return None, "нет .py"
    proc = subprocess.run(
        [sys.executable, "-m", "flake8", "--jobs=1", str(sol)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    lines = [ln for ln in out.splitlines() if ln.strip()]
    return len(lines), f"{len(lines)} замечаний"


def score_c09_flake8() -> tuple[float, str]:
    """PEP8/flake8 для кода в src_solution."""
    n, note = run_flake8_src_solution()
    if n is None:
        return 0.0, note
    if n == 0:
        return 3.0, "0 замечаний flake8"
    if n <= 5:
        return 2.0, note
    return 0.0, note


def _cyclonedx_has_numpy(data: dict | None) -> bool:
    """Ищет в CycloneDX JSON упоминание numpy в компонентах/зависимостях."""

    def walk(obj: object) -> bool:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in ("name", "bom-ref", "ref", "purl") and isinstance(v, str):
                    if "numpy" in v.lower():
                        return True
                if walk(v):
                    return True
        elif isinstance(obj, list):
            for item in obj:
                if walk(item):
                    return True
        return False

    return walk(data) if data else False


def _cyclonedx_looks_valid(data: dict | None) -> bool:
    if not data or not isinstance(data, dict):
        return False
    return "components" in data or data.get("bomFormat") == "CycloneDX" or "metadata" in data


def score_c14_numpy_sbom_split() -> tuple[float, str]:
    """
    Размещение numpy в SBOM решения, макс. 3:
    0 — numpy в SBOM_TCB; 3 — только в SBOM_OTHER и оба файла валидны; 1–2 — промежуточные.
    """
    tcb_path = ROOT / "src_solution" / "sbom" / "SBOM_TCB.cdx.json"
    other_path = ROOT / "src_solution" / "sbom" / "SBOM_OTHER.cdx.json"

    def load_json(p: Path) -> dict | None:
        if not p.is_file():
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            return None

    tcb = load_json(tcb_path)
    other = load_json(other_path)

    if tcb is None and other is None:
        return 1.0, "нет SBOM в src_solution/sbom"

    numpy_in_tcb = _cyclonedx_has_numpy(tcb)
    numpy_in_other = _cyclonedx_has_numpy(other)

    if numpy_in_tcb:
        return 0.0, "numpy в SBOM_TCB"
    if numpy_in_other:
        if _cyclonedx_looks_valid(tcb) and _cyclonedx_looks_valid(other):
            return 3.0, "numpy только в SBOM_OTHER, SBOM валидны"
        return 2.0, "numpy только в SBOM_OTHER"
    if _cyclonedx_looks_valid(tcb) and _cyclonedx_looks_valid(other):
        return 2.0, "numpy не в SBOM, файлы присутствуют"
    return 1.0, "numpy не в SBOM"


def score_c13_security_tests_links_solution() -> tuple[float, str]:
    """docs/security_tests.md: уровни по явным путям src_solution/ (ссылки, backticks)."""
    p = ROOT / "docs" / "security_tests.md"
    if not p.is_file():
        return 0.0, "нет docs/security_tests.md"
    try:
        txt = p.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return 0.0, str(e)

    path_link = bool(
        re.search(r"`src_solution/[^`\s]+`", txt)
        or re.search(r"\[[^\]]+\]\([^)]*src_solution[^)]*\)", txt)
        or re.search(r"src_solution/[^\s\)]+", txt)
    )
    n_paths = len(re.findall(r"src_solution/[^\s\)`]+", txt))
    plain = "src_solution" in txt

    if path_link and n_paths >= 3:
        return 3.0, f"явные пути ({n_paths})"
    if path_link:
        return 2.0, "есть путь/ссылка src_solution/"
    if plain:
        return 1.0, "упоминание src_solution без явного пути"
    return 0.0, "нет привязки к src_solution"


def score_c11_dependencies() -> tuple[float, str]:
    """C11: пустой файл — не выше 1 балла."""
    sol_req = ROOT / "src_solution" / "requirements.txt"
    sol_py = ROOT / "src_solution" / "pyproject.toml"
    if not sol_req.is_file() and not sol_py.is_file():
        return 0.0, "нет requirements.txt / pyproject.toml"

    if sol_req.is_file():
        body = sol_req.read_text(encoding="utf-8", errors="replace").strip()
        lines = [ln for ln in body.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        if not lines:
            return 1.0, "requirements.txt пустой"
        if len(lines) == 1:
            return 2.0, "одна зависимость"
        return 3.0, f"{len(lines)} зависимостей в requirements.txt"

    body = sol_py.read_text(encoding="utf-8", errors="replace")
    if len(body.strip()) < 20:
        return 1.0, "pyproject.toml почти пуст"
    if "[project]" in body or "[tool.poetry" in body:
        return 3.0, "pyproject с секцией проекта"
    return 2.0, "pyproject.toml без явной секции зависимостей"


def score_c17_solution_md() -> tuple[float, str]:
    """Наличие и полнота docs/solution.md (эвристика по ключевым разделам)."""
    if not SOLUTION_MD_PATH.is_file():
        return 0.0, "нет docs/solution.md"
    try:
        text = SOLUTION_MD_PATH.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return 0.0, str(e)
    lower = text.lower()
    if len(lower.strip()) < 50:
        return 0.0, "пусто или слишком кратко"

    has_arch = any(
        k in lower
        for k in (
            "архитектур",
            "компонент",
            "модуль",
            "abu",
            "двб",
            "разделен",
            "монитор",
        )
    )
    has_pol = "политик" in lower or ("цел" in lower and "безопас" in lower)
    has_e2e = "сквозн" in lower or "e2e" in lower or ("цр" in lower and "абу" in lower)
    has_sec = ("безопасност" in lower and "тест" in lower) or "tests/security" in lower
    has_cert = "сертификат" in lower or "сертификац" in lower
    has_diag = any(
        k in lower
        for k in (
            "диаграмм",
            "diagram",
            "mermaid",
            "plantuml",
            "![",
            ".png",
            ".svg",
        )
    )

    if not has_arch:
        return 0.0, "нет описания архитектуры"
    if not ((has_e2e or has_sec) or has_cert):
        return 0.0, "нет результатов тестов/сертификации"

    core = has_arch and has_pol and has_e2e and has_sec and has_cert
    if core and has_diag:
        return 3.0, "архитектура, политики, сквозные и security-тесты, сертификация, диаграммы"
    if core and not has_diag:
        return 1.0, "нет архитектурных диаграмм (остальное есть)"
    missing: list[str] = []
    if not has_e2e:
        missing.append("сквозные тесты")
    if not has_sec:
        missing.append("тесты безопасности")
    if not has_cert:
        missing.append("сертификация")
    if len(missing) == 1 and has_arch and has_pol:
        return 2.0, f"не хватает: {missing[0]}"
    return 1.0, "частично"


def criterion_table(
    pytest_rc: int | None,
    tcb_cov_pct: float | None,
) -> list[tuple[str, float, str]]:
    """
    22 критерия; значение 0..3.
    pytest_rc: None если пропуск прогона; tcb_cov_pct из прогона с --cov=src_solution.abu.tcb.
    """
    rows: list[tuple[str, float, str]] = []

    def add(name: str, value: float, note: str, cap: float = 3.0) -> None:
        v = max(0.0, min(cap, float(value)))
        rows.append((name, v, note))

    pytest_skipped = pytest_rc is None
    e2e_exists = E2E_TEST_PATH.is_file()

    # C01
    if pytest_skipped:
        add(
            "C01: Все тесты репозитория (включая тесты решения) завершаются успешно",
            0.0,
            "пропуск (--no-pytest)",
        )
    else:
        add(
            "C01: Все тесты репозитория (включая тесты решения) завершаются успешно",
            3.0 if pytest_rc == 0 else 0.0,
            "OK" if pytest_rc == 0 else f"exit {pytest_rc}",
        )

    # C02
    sec_files = _security_test_files()
    nsec = len(sec_files)
    if nsec >= 4:
        c02 = 3.0
    elif nsec == 3:
        c02 = 2.0
    elif nsec in (1, 2):
        c02 = 1.0
    else:
        c02 = 0.0
    add("C02: Наличие тестов безопасности (tests/security/ или src_starting_point/tests/security/)", c02, f"{nsec} файлов test_*.py")

    # C03
    if not _pytest_ini_has_security_marker():
        c03 = 0.0
        n03 = "нет pytest.ini или маркера security"
    else:
        mused = _security_marker_used_in_tests()
        if mused >= 3:
            c03 = 3.0
            n03 = f"маркер security используется ({mused} файлов)"
        elif mused >= 1:
            c03 = 2.0
            n03 = f"маркер security в тестах ({mused} файлов)"
        else:
            c03 = 1.0
            n03 = "pytest.ini с security, маркер не использован в тестах"
    add("C03: Маркер security в pytest.ini и использование в тестах", c03, n03)

    # C04
    ev = ROOT / "src_starting_point" / "tests" / "test_event_log.py"
    if not ev.is_file():
        add("C04: Покрытие тестами event_log / журнал", 0.0, "нет test_event_log.py")
    else:
        nf = _count_test_functions(ev)
        if nf >= 4:
            c04, n04 = 3.0, f"{nf} тестовых функций"
        elif nf >= 2:
            c04, n04 = 2.0, f"{nf} тестовых функций"
        else:
            c04, n04 = 1.0, f"{nf} тестовых функций"
        add("C04: Покрытие тестами event_log / журнал", c04, n04)

    # C05
    sga = ROOT / "docs" / "examples" / "sga.json"
    if not sga.is_file():
        add("C05: Пример sga.json", 0.0, "нет docs/examples/sga.json")
    else:
        try:
            data = json.loads(sga.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            add("C05: Пример sga.json", 1.0, "файл не JSON")
        else:
            if isinstance(data, dict) and len(data) >= 2:
                add("C05: Пример sga.json", 3.0, "валидный JSON, несколько ключей")
            elif isinstance(data, dict) and data:
                add("C05: Пример sga.json", 2.0, "валидный JSON")
            else:
                add("C05: Пример sga.json", 1.0, "JSON минимальный")

    # C06
    tcb_e = ROOT / "docs" / "examples" / "SBOM_TCB.cdx.json"
    oth_e = ROOT / "docs" / "examples" / "SBOM_OTHER.cdx.json"
    if not tcb_e.is_file() or not oth_e.is_file():
        add("C06: SBOM TCB / OTHER в примерах", 0.0, "нет обоих файлов в docs/examples/")
    else:
        try:
            jt = json.loads(tcb_e.read_text(encoding="utf-8", errors="replace"))
            jo = json.loads(oth_e.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            add("C06: SBOM TCB / OTHER в примерах", 1.0, "файлы не JSON")
        else:
            if _cyclonedx_looks_valid(jt) and _cyclonedx_looks_valid(jo):
                add("C06: SBOM TCB / OTHER в примерах", 3.0, "CycloneDX валиден")
            else:
                add("C06: SBOM TCB / OTHER в примерах", 2.0, "JSON без полной структуры CycloneDX")

    # C07
    prep = ROOT / "scripts" / "prepare_certification_bundle.sh"
    if not prep.is_file():
        add("C07: Скрипт prepare_certification_bundle.sh", 0.0, "нет scripts/prepare_certification_bundle.sh")
    else:
        try:
            body = prep.read_text(encoding="utf-8", errors="replace")
        except OSError:
            body = ""
        if len(body.strip()) < 50:
            add("C07: Скрипт prepare_certification_bundle.sh", 1.0, "скрипт почти пуст")
        elif body.startswith("#!") and "bash" in body[:20]:
            add("C07: Скрипт prepare_certification_bundle.sh", 3.0, "bash-скрипт с shebang")
        else:
            add("C07: Скрипт prepare_certification_bundle.sh", 2.0, "скрипт присутствует")

    # C08
    if not e2e_exists:
        add("C08: Сквозной автотест ЦР–АБУ (основной сценарий)", 0.0, "нет test_e2e_abu_dm_scenario.py")
    elif pytest_skipped:
        add("C08: Сквозной автотест ЦР–АБУ (основной сценарий)", 2.0, "файл есть; пропуск pytest")
    elif pytest_rc == 0:
        add("C08: Сквозной автотест ЦР–АБУ (основной сценарий)", 3.0, "pytest OK")
    else:
        add("C08: Сквозной автотест ЦР–АБУ (основной сценарий)", 0.0, "pytest упал")

    c09, n09 = score_c09_flake8()
    add("C09: Оформление кода в src_solution (flake8, PEP8)", c09, n09)

    py_sol, blob_sol = _src_solution_snapshot()
    lower_sol = blob_sol.lower()

    # C10
    if not py_sol:
        add("C10: Решение: журнал событий / event_log в src_solution", 0.0, "нет .py в src_solution")
    elif any("event_log" in str(p).lower() for p in py_sol):
        add("C10: Решение: журнал событий / event_log в src_solution", 3.0, "модуль event_log в дереве")
    elif "event_log" in lower_sol:
        add("C10: Решение: журнал событий / event_log в src_solution", 2.0, "event_log в коде")
    else:
        add("C10: Решение: журнал событий / event_log в src_solution", 1.0, "есть код без event_log")

    c11, n11 = score_c11_dependencies()
    add("C11: Решение: зависимости (requirements / pyproject в src_solution)", c11, n11)

    # C12 — только AST-импорты src_solution из tests/
    t_imp = _test_files_importing_src_solution()
    nt = len(t_imp)
    if nt >= 3:
        c12 = 3.0
    elif nt == 2:
        c12 = 2.0
    elif nt == 1:
        c12 = 1.0
    else:
        c12 = 0.0
    add(
        "C12: Тесты репозитория импортируют код из src_solution (AST)",
        c12,
        f"файлов с import src_solution: {nt}",
    )

    c13, n13 = score_c13_security_tests_links_solution()
    add("C13: docs/security_tests.md привязан к решению (src_solution)", c13, n13)

    c14, n14 = score_c14_numpy_sbom_split()
    add("C14: numpy в SBOM решения (SBOM_TCB vs SBOM_OTHER)", c14, n14, cap=3.0)

    # C15
    t_both = _test_files_importing_event_log_and_src_solution()
    nb = len(t_both)
    if nb >= 2:
        c15 = 3.0
    elif nb == 1:
        c15 = 2.0
    else:
        c15 = 0.0
    add(
        "C15: Тесты: журнал event_log и решение (импорты из src_solution + event_log)",
        c15,
        f"файлов: {nb}",
    )

    c16, n16 = score_c16_tcb_coverage(tcb_cov_pct, pytest_skipped)
    add("C16: Покрытие ДВБ решения (src_solution/abu/tcb) тестами", c16, n16)

    c17, n17 = score_c17_solution_md()
    add("C17: Отчёт конкурсанта (docs/solution.md)", c17, n17)

    c18, c19, n18, n19 = score_c18_c19_solution(py_sol, blob_sol)
    add(
        "C18: security_monitor, policies в src_solution; тесты политик",
        c18,
        n18,
    )
    add(
        "C19: изоляция доменов; монитор запросов/ответов",
        c19,
        n19,
    )
    add(
        "C20: Стоимость сертификации — место в рейтинге (жюри: 3 / 2 / 1 / 0)",
        0.0,
        "автоматика 0; жюри после сравнения всех участников",
    )
    add(
        "C21: Экспертно — соответствие политик архитектуре АБУ (жюри)",
        0.0,
        "автоматика 0; заполняет жюри",
    )
    add(
        "C22: Экспертно — полнота отчёта и воспроизводимость (жюри)",
        0.0,
        "автоматика 0; заполняет жюри",
    )

    assert len(rows) == 22, len(rows)
    return rows


def display_score(raw: float) -> float:
    """Нормализация в [10, 20] при raw ∈ [0, RAW_MAX]."""
    return 10.0 + (raw / RAW_MAX) * 10.0


def main() -> None:
    parser = argparse.ArgumentParser(description="Оценка прототипа по 22 критериям (макс. 3 за критерий).")
    parser.add_argument("--no-pytest", action="store_true", help="Не запускать pytest")
    parser.add_argument("--json", action="store_true", dest="json_out", help="JSON в stdout")
    args = parser.parse_args()

    pytest_rc: int | None = None
    tcb_cov_pct: float | None = None
    if not args.no_pytest:
        pytest_rc, tcb_cov_pct = run_pytest_with_tcb_coverage()

    rows = criterion_table(pytest_rc, tcb_cov_pct)
    raw = sum(v for _, v, _ in rows)
    disp = display_score(raw)

    if args.json_out:
        print(
            json.dumps(
                {
                    "raw_sum": raw,
                    "raw_max": RAW_MAX,
                    "display_score_10_20": round(disp, 2),
                    "criteria": [{"name": n, "score": v, "note": t} for n, v, t in rows],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        sys.exit(0)

    print(f"Оценка по критериям (0–3 за критерий; сумма до {RAW_MAX:.0f}):\n")
    for name, v, note in rows:
        print(f"  {name}: {v:.1f}  ({note})")
    print(f"\nСумма (raw): {raw:.1f} / {RAW_MAX:.0f}")
    print(f"Итоговая шкала 10–20: {disp:.2f}")
    print("\nОриентир для заготовки: итог обычно попадает в 10–20 при полном прогоне; при отклонении проверьте окружение Linux и Makefile.")

    if not (9.0 <= disp <= 21.0):
        print(
            f"\nПредупреждение: итог {disp:.2f} вне типичного диапазона [10, 20].",
            file=sys.stderr,
        )
    sys.exit(0)


if __name__ == "__main__":
    main()
