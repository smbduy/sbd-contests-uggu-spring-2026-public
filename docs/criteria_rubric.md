# Расшифровка критериев C01–C22 (уровни 0–3)

Источник автоматики: [`scripts/evaluate_contest_score.py`](../scripts/evaluate_contest_score.py). Имена функций в `pytest` **не** являются строками этой таблицы.

<a id="c01"></a>
### C01 — Все тесты репозитория
**Макс.** 3. **Артефакты:** `src_starting_point/tests/`, `tests/`; команда `make tests-all`.  
**Уровни:** 0 — падение pytest; 3 — успешное завершение.

<a id="c02"></a>
### C02 — Тесты безопасности
**Макс.** 3. **Артефакты:** [`tests/security/`](../tests/security/) и/или [`src_starting_point/tests/security/`](../src_starting_point/tests/security/) — файлы `test_*.py`.  
**Уровни:** 0 — нет файлов; 1 — один; 2 — два–три; 3 — четыре и более.

<a id="c03"></a>
### C03 — Маркер `security` в pytest
**Макс.** 3. **Артефакты:** [`pytest.ini`](../pytest.ini).  
**Уровни:** 0 — нет маркера; 1 — маркер объявлен; 2 — маркер используется в тестах (≥1 файл); 3 — в ≥3 файлах.

<a id="c04"></a>
### C04 — Тесты журнала / event_log
**Макс.** 3. **Артефакты:** [`src_starting_point/tests/test_event_log.py`](../src_starting_point/tests/test_event_log.py).  
**Уровни:** 0 — нет файла; 1 — одна тестовая функция; 2 — две–три; 3 — четыре и более.

<a id="c05"></a>
### C05 — Пример sga.json
**Макс.** 3. **Артефакты:** [`docs/examples/sga.json`](examples/sga.json).  
**Уровни:** 0 — нет; 1 — не JSON; 2 — валидный JSON; 3 — несколько ключей в объекте.

<a id="c06"></a>
### C06 — Примеры SBOM в docs/examples
**Макс.** 3. **Артефакты:** [`docs/examples/SBOM_TCB.cdx.json`](examples/SBOM_TCB.cdx.json), [`SBOM_OTHER.cdx.json`](examples/SBOM_OTHER.cdx.json).  
**Уровни:** 0 — нет пары файлов; 1–2 — JSON; 3 — структура CycloneDX.

<a id="c07"></a>
### C07 — Скрипт пакета сертификации
**Макс.** 3. **Артефакты:** [`scripts/prepare_certification_bundle.sh`](../scripts/prepare_certification_bundle.sh).  
**Уровни:** 0 — нет; 1 — почти пуст; 2 — есть содержимое; 3 — bash + shebang.

<a id="c08"></a>
### C08 — Сквозной автотест ЦР–АБУ
**Макс.** 3. **Артефакты:** [`tests/test_e2e_abu_dm_scenario.py`](../tests/test_e2e_abu_dm_scenario.py).  
**Уровни:** 0 — нет файла; 2 — пропуск pytest (`--no-pytest`); 3 — pytest OK; при падении тестов — 0.

<a id="c09"></a>
### C09 — Оформление кода в src_solution
**Макс.** 3. **Артефакты:** [`src_solution/`](../src_solution/).  
**Уровни:** 0 — >5 замечаний flake8 или нет .py; 2 — 1–5 замечаний; 3 — 0 замечаний.

<a id="c10"></a>
### C10 — Журнал event_log в решении
**Макс.** 3. **Артефакты:** дерево [`src_solution/`](../src_solution/).  
**Уровни:** 0 — нет .py; 1 — код без event_log; 2 — упоминание в коде; 3 — модуль `event_log` в пути.

<a id="c11"></a>
### C11 — Зависимости решения
**Макс.** 3. **Артефакты:** [`src_solution/requirements.txt`](../src_solution/requirements.txt), [`src_solution/pyproject.toml`](../src_solution/pyproject.toml).  
**Уровни:** 0 — нет файла; 1 — пустой или почти пуст; 2 — одна зависимость или слабый pyproject; 3 — несколько зависимостей или полноценный pyproject.

<a id="c12"></a>
### C12 — Тесты импортируют src_solution
**Макс.** 3. **Артефакты:** только [`tests/`](../tests/) (AST `import src_solution`).  
**Уровни:** 0 — нет импортов; 1 — один файл; 2 — два; 3 — три и более.

<a id="c13"></a>
### C13 — security_tests.md и решение
**Макс.** 3. **Артефакты:** [`docs/security_tests.md`](security_tests.md).  
**Уровни:** 0 — нет файла/привязки; 1 — текстовое упоминание; 2 — путь или ссылка `src_solution/`; 3 — несколько явных путей.

<a id="c14"></a>
### C14 — numpy в SBOM решения
**Макс.** 3. **Артефакты:** [`src_solution/sbom/SBOM_TCB.cdx.json`](../src_solution/sbom/SBOM_TCB.cdx.json), [`SBOM_OTHER.cdx.json`](../src_solution/sbom/SBOM_OTHER.cdx.json).  
**Уровни:** 0 — numpy в TCB; 1 — нет SBOM; 2 — numpy только в OTHER или не в SBOM; 3 — numpy только в OTHER и оба SBOM валидны.

<a id="c15"></a>
### C15 — Тесты event_log и src_solution
**Макс.** 3. **Артефакты:** [`tests/`](../tests/) (AST: импорт `src_solution` и `event_log`).  
**Уровни:** 0 — нет; 2 — один файл; 3 — два и более файлов.

<a id="c16"></a>
### C16 — Покрытие ДВБ (abu/tcb)
**Макс.** 3. Покрытие `src_solution.abu.tcb` из `pytest --cov`.  
**Уровни:** 0 — <40%; 1 — 40–59%; 2 — 60–79%; 3 — ≥80%.

<a id="c17"></a>
### C17 — Отчёт solution.md
**Макс.** 3. **Артефакты:** [`docs/solution.md`](solution.md).  
**Уровни:** см. эвристику в скрипте (архитектура, политики, тесты, сертификация, диаграммы).

<a id="c18"></a>
### C18 — security_monitor, policies
**Макс.** 3. **Артефакты:** [`src_solution/`](../src_solution/), тесты с импортом `src_solution`.  
**Уровни:** эвристика по коду и тестам (жюри может уточнить).

<a id="c19"></a>
### C19 — Домены и монитор
**Макс.** 3. **Артефакты:** [`src_solution/`](../src_solution/).  
**Уровни:** эвристика по ключевым словам (domains, monitor, request/response).

<a id="c20"></a>
### C20 — Стоимость сертификации
**Макс.** 3. **Жюри** (в скрипте 0).

<a id="c21"></a>
### C21 — Экспертно: политики и архитектура
**Макс.** 3. **Жюри** (в скрипте 0).

<a id="c22"></a>
### C22 — Экспертно: отчёт и воспроизводимость
**Макс.** 3. **Жюри** (в скрипте 0).
