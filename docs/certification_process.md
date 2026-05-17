# Процесс сертификации АБУ (прототип, пример `src_starting_point`)

Итоговая оценка работы по критериям C01--C22 и шкала 10--20 описаны в [contest_regulations.md](contest_regulations.md) и считаются скриптом `scripts/evaluate_contest_score.py` (часть критериев — экспертно).

## Предусловия

- Python 3.12+ (см. `[requires]` в [Pipfile](../Pipfile)); для классического `python3 -m venv` при необходимости — пакет `python3-venv` в Debian/Ubuntu.
- Зависимости **только в виртуальном окружении Pipenv** (см. [quality_requirements.md](quality_requirements.md)): `./scripts/bootstrap_pipenv.sh` или `make install` (создаёт `.venv/` через Pipenv и ставит пакеты из Pipfile). Не выполняйте `pip install` в системный Python.
- Для диаграмм (опционально): PlantUML с `JAVA_TOOL_OPTIONS=-Djava.awt.headless=true` при отсутствии дисплея.

## Шаг 1. Подготовка сертификационного пакета

Перед копированием вызывается **генерация** SBOM из манифеста [sbom_manifest.json](sbom_manifest.json) в `docs/examples/` (см. [sbom_guide.md](sbom_guide.md)). Затем скрипт копирует `src_starting_point`, примеры **SGA** (`docs/examples/sga.json` → `cert_bundle/security/sga.json`), раздельные CycloneDX **SBOM_TCB** и **SBOM_OTHER**, агрегированный `sbom/sbom.cdx.json` для совместимости, и формирует `manifest.json`, затем создаёт архив `artifacts/abu_certification_bundle.tar.gz`.

```bash
make prepare-cert-bundle
```

Или напрямую:

```bash
./scripts/prepare_certification_bundle.sh
```

## Шаг 2. Запуск Регулятора и подача заявки

### Вариант A: цель Makefile

```bash
make certify-abu
```

В стандартный вывод выводятся:

- **результат** — успешно / неуспешно;
- **стоимость** — `estimated_cost`;
- **сертификат** — `certificate_id` (SHA-256 архива пакета).

### Вариант B: полный набор тестов (pytest)

```bash
make tests-all
```

Включает интеграционный тест полного цикла сертификации для того же пакета.

### Вариант C: ручной HTTP (локально)

Поднимите Регулятор (`uvicorn regulator.main:app`) и выполните `POST /api/v1/certification/requests` с полями:

- `bundle_path` — абсолютный путь к `artifacts/abu_certification_bundle.tar.gz` **на машине, где работает процесс Регулятора**;
- `developer_company` (опционально) — название компании-разработчика;
- `firmware_label` (опционально) — метка прошивки; если пусто, подставляется `package_name` из `manifest.json` пакета.

### Вариант D: Docker и загрузка архива

1. Сборка и запуск: `make docker-build`, затем `make docker-up` (или `./scripts/docker_build.sh`, `./scripts/docker_up.sh`). Сервисы: Регулятор — порт **8082**, ЦР — **8080**, АБУ — **8081**.
2. Загрузка пакета телом запроса (без общего диска с хостом): `POST /api/v1/certification/upload` — `multipart/form-data` с полем файла `bundle` (`.tar.gz`) и при необходимости полями формы `developer_company`, `firmware_label`.
3. Сводная таблица успешных сертификаций: `GET /api/v1/certification/summary` (компания, прошивка, стоимость, покрытие, время).
4. Примеры запросов для расширения REST Client: корневой файл [requests.rest](../requests.rest).

Интеграционные тесты по HTTP к Регулятору в Docker: поднять контейнер Регулятора, затем `pytest tests/test_docker_integration.py` (или полный `make tests-all` — тесты пропускаются, если сервис недоступен). Явный пропуск: `SKIP_DOCKER_TESTS=1`. URL Регулятора: переменная `REGULATOR_URL` (по умолчанию `http://127.0.0.1:8082`).

## Шаг 3. Ввод в эксплуатацию

1. Сохраните `certificate_id` из ответа.
2. Зарегистрируйте АБУ в ЦР, передав `certificate_id`.
3. Для строгого режима установите `CR_CERT_POLICY=strict`.

## Пример ожидаемого вывода `make certify-abu`

```
Результат сертификации: успешно
Стоимость (усл. ед.): 12345.67
Сертификат (SHA-256 пакета): abcd1234...ef
```

Точные числа зависят от размера SBOM, **метрик исходников ДВБ** (число строк `*.py` в пакете `abu` --- `tcb_lines_of_code`, сумма цикломатических сложностей функций --- `tcb_cyclomatic_sum`) и результатов `pytest`. Эти величины входят в расчёт `estimated_cost` (см. [docs/bundle/sections/03-certification.tex](bundle/sections/03-certification.tex) в PDF-пакете). В ответе также указываются покрытие кода и **покрытие тестами безопасности** (`security_coverage_percent`). SGA пакета доступен по `GET /api/v1/certificates/{certificate_id}/sga` после успешной выдачи сертификата.

Оценка решения по регламенту: `make evaluate-score` ([contest_regulations.md](contest_regulations.md), [templates/evaluation_report.md](templates/evaluation_report.md)).
