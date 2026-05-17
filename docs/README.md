# Документация репозитория (индекс)

**Редакция пакета документов: 1.7.7.** Начните с одного линейного маршрута, затем углубляйтесь по ссылкам.

## Маршрут чтения (6 шагов)

1. **[contest_task.md](contest_task.md)** — задание, user story, что сдавать.  
2. **[contest_regulations.md](contest_regulations.md)** — критерии C01–C22, уровни 0–3, сдача.  
3. **[context.md](context.md)** — предметная область (ЦР, АБУ, сертификация).  
4. **[architecture.md](architecture.md)** — архитектура и ДВБ.  
5. **[quality_requirements.md](quality_requirements.md)** — окружение Python, тесты, git.  
6. **[certification_process.md](certification_process.md)** — шаги сертификации и команды.

## Мини-оглавление по критериям

Полная расшифровка уровней **0–3** и путей к файлам: **[criteria_rubric.md](criteria_rubric.md)** (якоря `#c01` … `#c22`).

## Оценка и отчёт

- Скрипт баллов: [scripts/evaluate_contest_score.py](../scripts/evaluate_contest_score.py), команда `make evaluate-score`.  
- Отчёт участника: [solution.md](solution.md).  
- Шаблон таблицы баллов: [templates/evaluation_report.md](templates/evaluation_report.md).

## Прочее

| Тема | Документ |
|------|----------|
| SBOM, CycloneDX | [sbom_guide.md](sbom_guide.md) |
| Тесты безопасности vs SG | [security_tests.md](security_tests.md) |
| TARA | [tara_abu.md](tara_abu.md) |
| Сборка PDF (LaTeX) | [bundle/README.md](bundle/README.md) |
