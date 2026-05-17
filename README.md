# Конкурсное задание: АБУ и цифровой рудник

Прототип учебного стенда: **автономная буровая установка (АБУ)** как киберфизическая система, **цифровой рудник (ЦР)** как надсистема координации и **Регулятор** — служба сертификации поставки ПО АБУ. Проект ориентирован на требования **ГОСТ Р 72118-2025** (цели и предположения безопасности, ДВБ, SBOM) и практики **ISO/SAE 21434** (моделирование угроз, TARA).

**Редакция документации и критериев: 1.7.7.**

## С чего начать (линейный маршрут)

1. **[docs/contest_task.md](docs/contest_task.md)** — формулировка задания, user story, что сдавать (читать **первым**).
2. **[docs/contest_regulations.md](docs/contest_regulations.md)** — 22 критерия **C01–C22**, уровни **0–3** балла каждый, сумма raw до **66**, нормализация итога в **10–20**.
3. **[docs/context.md](docs/context.md)** и **[docs/architecture.md](docs/architecture.md)** — предметная область и архитектура (после п. 1–2).
4. **[docs/quality_requirements.md](docs/quality_requirements.md)** — окружение Python; затем `make install`.
5. `make tests-all` — проверка тестов.
6. **[docs/certification_process.md](docs/certification_process.md)** — сертификация: `make prepare-cert-bundle`, `make certify-abu`.
7. Критерии с расшифровкой и ссылками на файлы: **[docs/criteria_rubric.md](docs/criteria_rubric.md)**; индекс всей документации — **[docs/README.md](docs/README.md)**.

Имена тестов в `pytest` и комментарии в коде **не** являются строками таблицы баллов: итог по критериям даёт **`make evaluate-score`** ([`scripts/evaluate_contest_score.py`](scripts/evaluate_contest_score.py)) и шаблон [docs/templates/evaluation_report.md](docs/templates/evaluation_report.md).

## Платформа: Linux и окружение

**Эталонная среда для проверки жюри и команд Makefile — Linux** (bash, POSIX-пути). На **Windows** без **WSL2**, **Docker** или **GitHub Codespaces** часто возникают ошибки (`make`, `pipenv`, разделители путей).

- **GitHub Codespaces:** откройте репозиторий на GitHub → **Code** → **Codespaces** → **Create codespace on main** → в терминале: `make install`, `make tests-all`.
- **WSL2** (Windows): установите дистрибутив Linux, клонируйте репозиторий в файловую систему WSL и выполняйте те же команды, что в инструкции.
- Разработка на любой ОС допустима, если в сдаче **воспроизводимо** проходят тесты; официальная проверка выполняется в среде, согласованной с жюри (как правило **Linux**).

При наличии [`.devcontainer/devcontainer.json`](.devcontainer/devcontainer.json) можно открыть репозиторий в контейнере (VS Code / Codespaces) с предустановленными зависимостями.

## Контекст

| Компонент | Роль |
|-----------|------|
| **ЦР** | Регистрация установок, миссии, политика сертификатов (`CR_CERT_POLICY`), проверка **SGA** (ЦПБ) через Регулятор, учёт стоимости поддержки. |
| **АБУ** | Исполнение миссий, телеметрия, псевдо-ИИ и проверки безопасности; в заготовке — намеренный технический долг (ДВБ не отделена от остального кода). |
| **Регулятор** | Приём сертификационного пакета (исходники, **SGA**, **SBOM_TCB** / **SBOM_OTHER**), песочница с `pytest` и покрытием, в т.ч. отдельный прогон **тестов безопасности**, выдача **сертификата** (хэш пакета) и оценки стоимости. |

В коде и API используется термин **SGA** (*security goals and assumptions*); в текстах регламента допустимо **ЦПБ**.

## Структура репозитория

| Каталог / файл | Назначение |
|----------------|------------|
| [src_starting_point/](src_starting_point/) | Заготовка АБУ (отправная точка для конкурсантов; намеренно неоптимальна как образец архитектуры). |
| [src_solution/](src_solution/) | Рабочая зона решения: `abu/tcb` (ДВБ), `abu/other`, `sbom/SBOM_*.cdx.json` (не изменяется организаторами без отдельной договорённости). |
| [external_systems/digital_mine/](external_systems/digital_mine/) | Прототип ЦР. |
| [external_systems/regulator/](external_systems/regulator/) | Прототип Регулятора. |
| [tests/](tests/) | Интеграционные и прочие тесты репозитория. |
| [docs/](docs/) | Архитектура, сценарии, процесс сертификации, регламент, TARA. |
| [Makefile](Makefile) | `install`, `tests-all`, подготовка пакета, сертификация, оценка, Docker. |

## Полезные документы

| Документ | Содержание |
|----------|------------|
| [docs/contest_task.md](docs/contest_task.md) | Задание и user story (**начать отсюда**). |
| [docs/criteria_rubric.md](docs/criteria_rubric.md) | C01–C22, уровни 0–3, пути к файлам. |
| [docs/quality_requirements.md](docs/quality_requirements.md) | Окружение Python, тесты, changelog, git. |
| [docs/certification_process.md](docs/certification_process.md) | Пошаговая сертификация и примеры. |
| [docs/sbom_guide.md](docs/sbom_guide.md) | SBOM_TCB / SBOM_OTHER, манифест, генерация CycloneDX. |
| [docs/security_tests.md](docs/security_tests.md) | Связь целей безопасности (SG) и тестов. |
| [docs/tara_abu.md](docs/tara_abu.md) | TARA, диаграммы угроз. |
| [docs/contest_regulations.md](docs/contest_regulations.md) | Регламент, tie-break, формат сдачи. |
| [docs/operational_scenario_v1.md](docs/operational_scenario_v1.md) | Сценарий эксплуатации. |
| [docs/scope_two_day.md](docs/scope_two_day.md) | Ограничение по времени на задачу. |
| [docs/slides/README.md](docs/slides/README.md) | Презентация Beamer, сборка PDF (`build_pdf.sh`). |
| [requests.rest](requests.rest) | Примеры HTTP (REST Client). |

## Окружение и проверки

- **Python 3.12+**, зависимости из [Pipfile](Pipfile) / [Pipfile.lock](Pipfile.lock); команды через `make` и `pipenv run …`.
- Установка: `make install`.
- Все тесты: `make tests-all`.
- Оценка по критериям: `make evaluate-score` (сумма raw до **66**, итог **10 + (raw/66)×10**).
- Docker (опционально): `make docker-build`, `make docker-up` — см. скрипты в [scripts/](scripts/).

Не устанавливайте пакеты в системный интерпретатор: см. раздел «Окружение» в [docs/quality_requirements.md](docs/quality_requirements.md).

## На что обратить внимание для баллов

По [регламенту](docs/contest_regulations.md) и скрипту [scripts/evaluate_contest_score.py](scripts/evaluate_contest_score.py) наибольший вес дают:

- **Стабильное прохождение тестов** (`make tests-all`) и осмысленные **тесты безопасности** с покрытием критичного кода.
- **Сертификация через Регулятор**: корректный пакет с **SGA** и раздельным **SBOM** (TCB / OTHER), осмысленная **модель стоимости** и зависимостей ДВБ.
- **Архитектура и ДВБ**: разделение доверенного кода, обоснование в документации, **TARA** и сопоставление целей с тестами.
- **Отчёт о решении** [docs/solution.md](docs/solution.md) (C17), структура **ДВБ** (`src_solution/abu/tcb`), **SBOM решения** (`src_solution/sbom/`), и **таблица баллов** по [docs/templates/evaluation_report.md](docs/templates/evaluation_report.md) ([пример](docs/templates/evaluation_report_example.md)).
- **Решение в `src_solution/`:** по регламенту оцениваются в т.ч. **security_monitor**, **policies**, изоляция доменов и контроль запросов/ответов (C18–C19); ориентир — [пример с изоляцией в учебном ноутбуке](https://github.com/cyberimmunity-edu/cyberimmune-systems-example-traffic-light-jupyter-notebook/blob/master/cyberimmunity-traffic-lights-example.ipynb) (см. также [docs/architecture.md](docs/architecture.md)).

## Лицензия и состав

В репозитории хранятся исходный код, документация и скрипты; временные артефакты (например `artifacts/`, локальные логи) не коммитятся — см. [.gitignore](.gitignore).
