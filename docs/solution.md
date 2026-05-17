# Отчёт о конкурсном решении

**Участник / команда:** smbduy
**Дата:** 2026-05-17

---

## 1. Архитектура решения

### 1.1 Структура кода

Решение размещено в `src_solution/` и разделено на два домена безопасности:

```
src_solution/
├── abu/
│   ├── tcb/                          # ДВБ (доверенная вычислительная база)
│   │   ├── ipc.py                    # Канонический формат Event
│   │   ├── route_monitor.py          # Маршрутный монитор (default deny)
│   │   ├── domain_guard.py           # Egress/ingress политики доменов
│   │   ├── parameter_guard.py        # Валидация параметров операций
│   │   ├── security_monitor.py       # Единый монитор безопасности
│   │   ├── safety.py                 # Критичные проверки (БЕЗ зависимости от other!)
│   │   ├── event_log.py              # Журнал событий
│   │   └── placeholder.py            # Заглушка health-check
│   ├── other/                        # Недоверенный код
│   │   ├── pseudo_ai.py              # Эвристики ИИ
│   │   └── numpy_workflow.py         # Вычисления на numpy
│   ├── app.py                        # FastAPI приложение
│   └── ipc_policies.json             # Политики IPC (whitelist)
├── sbom/
│   ├── SBOM_TCB.cdx.json             # numpy НЕТ в ДВБ!
│   ├── SBOM_OTHER.cdx.json           # numpy ЗДЕСЬ
│   └── sbom_manifest.json
├── tests/security/                   # 4+ файла тестов безопасности
└── requirements.txt
```

### 1.2 Границы ДВБ

Доверенная вычислительная база (ДВБ) включает только код, критичный для целей безопасности (SG):

- **ipc.py** — формат IPC-события (Event dataclass, frozen)
- **route_monitor.py** — маршрутный монитор с default deny и whitelist из ipc_policies.json
- **domain_guard.py** — локальные egress/ingress правила доменов
- **parameter_guard.py** — семантическая валидация параметров операций
- **security_monitor.py** — фасад, объединяющий три слоя проверки
- **safety.py** — проверки безопасности (enforce_depth_cap, enforce_rpm_cap, should_emergency_stop, check_safety_constraints)
- **event_log.py** — журнал событий безопасности (SG_ADS_Security_events_store)

Код вне ДВБ (`abu/other/`) — pseudo_ai.py и numpy_workflow.py — при компрометации не может нарушить SG, поскольку все критичные решения принимаются в ДВБ, а взаимодействие доменов контролируется SecurityMonitor.

### 1.3 Ключевое отличие от заготовки

В заготовке `src_starting_point/abu/safety.py` функция `should_emergency_stop` импортирует `anomaly_vibration` из `pseudo_ai.py` — это нарушает границу ДВБ, поскольку доверенный код зависит от недоверенного. В решении `safety.py` получает `vibration_score` как параметр, а не вычисляет сам, что гарантирует независимость ДВБ от компрометации other/.

---

## 2. Политики безопасности и цели (ЦПБ)

### 2.1 Цели безопасности (SG)

| Идентификатор | Формулировка | Как обеспечивается |
|---------------|-------------|-------------------|
| SG_ADS_Authorized_critical_commands | При любых обстоятельствах выполняются только авторизованные критичные команды | SecurityMonitor с default deny; все IPC-маршруты проходят через whitelist в ipc_policies.json |
| SG_ADS_Controlled_operations | При любых обстоятельствах соблюдаются критичные ограничения | safety.py в ДВБ: enforce_depth_cap, enforce_rpm_cap, should_emergency_stop — не зависят от other/ |
| SG_ADS_Security_events_store | При любых обстоятельствах сохраняются события безопасности | event_log.py в ДВБ: потокобезопасный кольцевой буфер и полный журнал в файле |

### 2.2 Предположения безопасности (SA)

| Идентификатор | Формулировка |
|---------------|-------------|
| SA_ADS_Trustrworthy_authorized_operators | Авторизованные сотрудники ЦР являются благонадёжными |

### 2.3 Политики IPC

Файл `src_solution/abu/ipc_policies.json` содержит минимальный набор разрешённых маршрутов (13 правил). Default deny: любой маршрут, не перечисленный в whitelist, отклоняется.

Разрешённые взаимодействия:
- `http_api → safety_controller`: start_mission, tick_step, get_status, health_check
- `http_api → pseudo_ai`: ai_suggest
- `http_api → event_log`: record, ring_snapshot, read_full_tail
- `safety_controller → pseudo_ai`: regime_suggest, anomaly_vibration, risk_flag
- `safety_controller → event_log`: record
- `pseudo_ai → event_log`: record

Запрещённые примеры (default deny):
- `pseudo_ai → safety_controller` — ИИ не может отправлять команды контроллеру
- `event_log → pseudo_ai` — журнал не может вызывать ИИ
- `http_api → safety_controller: unknown_op` — неизвестные операции отклоняются

---

## 3. Результаты сквозных тестов

Команда запуска: `python3 -m pytest src_starting_point/tests tests/test_e2e_abu_dm_scenario.py -q`

Сквозной сценарий ЦР–АБУ (`tests/test_e2e_abu_dm_scenario.py`) регистрирует буровую установку в ЦР, создаёт миссию и проверяет, что АБУ принимает задание. Тест проходит успешно.

---

## 4. Результаты тестов безопасности

### 4.1 Тесты безопасности (маркер `security`)

4 файла с тестами безопасности в `src_solution/tests/security/`:

| Цель (SG) | Файл тестов | Функций |
|-----------|-------------|---------|
| SG_ADS_Authorized_critical_commands | `src_solution/tests/security/test_sg_authorized_commands.py` | 6 |
| SG_ADS_Controlled_operations | `src_solution/tests/security/test_sg_controlled_ops.py` | 7 |
| SG_ADS_Security_events_store | `src_solution/tests/security/test_sg_security_events.py` | 4 |
| Монитор + политики | `src_solution/tests/security/test_sg_monitor_policies.py` | 12 |

### 4.2 Таблица тестов безопасности

| Цель (SG) | Файлы тестов в `src_solution/tests` | Проверяемые файлы в `src_solution` | Комментарий |
|-----------|--------------------------------------|-------------------------------------|-------------|
| SG_ADS_Authorized_critical_commands | `src_solution/tests/security/test_sg_authorized_commands.py` | `src_solution/abu/tcb/safety.py` | enforce_depth_cap, enforce_rpm_cap |
| SG_ADS_Controlled_operations | `src_solution/tests/security/test_sg_controlled_ops.py` | `src_solution/abu/tcb/safety.py` | should_emergency_stop, check_safety_constraints |
| SG_ADS_Security_events_store | `src_solution/tests/security/test_sg_security_events.py` | `src_solution/abu/tcb/event_log.py` | Кольцо, полный журнал, потокобезопасность |
| Монитор и политики | `src_solution/tests/security/test_sg_monitor_policies.py` | `src_solution/abu/tcb/security_monitor.py`, `route_monitor.py`, `domain_guard.py`, `parameter_guard.py` | Default deny, whitelist, egress/ingress, параметры |

---

## 5. Сертификация

Для сертификации решения используется отдельный скрипт:
```bash
make prepare-cert-bundle-solution
make certify-abu-solution
```

Ключевые моменты:
- **SBOM_TCB** содержит только `abu-safety-controller` без numpy — 0 рёбер зависимостей
- **SBOM_OTHER** содержит fastapi, uvicorn, pydantic, httpx, numpy
- numpy вынесена из ДВБ, что исключает удвоение стоимости сертификации (HEAVY_DEP_COST_MULTIPLIER)
- Минимальное число рёбер в SBOM_TCB снижает полиномиальную составляющую стоимости

---

## 6. Архитектурные диаграммы

### 6.1 Домены безопасности и IPC

```
┌─────────────────────────────────────────────────────────┐
│                    SecurityMonitor                       │
│  ┌──────────────┐ ┌──────────────┐ ┌─────────────────┐ │
│  │ RouteMonitor  │ │ DomainGuard  │ │ ParameterGuard  │ │
│  │ (default deny)│ │ (egress/ing) │ │ (validation)    │ │
│  └──────────────┘ └──────────────┘ └─────────────────┘ │
└──────────────────────────┬──────────────────────────────┘
                           │ check(event)
          ┌────────────────┼───────────────────┐
          ▼                ▼                   ▼
  ┌───────────────┐ ┌─────────────┐  ┌──────────────┐
  │  http_api     │ │ safety_     │  │  pseudo_ai   │
  │  (other)      │ │ controller  │  │  (other)     │
  │               │ │ (tcb)       │  │              │
  └───────┬───────┘ └──────┬──────┘  └──────┬───────┘
          │                │                 │
          │    ┌───────────┼─────────────────┤
          │    ▼           ▼                 ▼
          │  ┌─────────────────────────────────┐
          │  │         event_log (tcb)         │
          │  │   ring buffer + full log        │
          │  └─────────────────────────────────┘
          │
          ▼
     FastAPI HTTP
```

### 6.2 Последовательность tick_step

```
HTTP API ──Event──▶ SecurityMonitor ──check──▶ ✅/❌
    │                                           │
    │ (если ✅)                                 │
    ▼                                           │
safety_controller ◀──Event── http_api:tick_step │
    │                                           │
    ├──Event──▶ pseudo_ai:regime_suggest ──▶ SecurityMonitor ──✅
    ├──Event──▶ pseudo_ai:risk_flag ──────▶ SecurityMonitor ──✅
    │                                           
    ├── check_safety_constraints (ДВБ, без зависимости от other)
    │                                           
    └──Event──▶ event_log:record ────────▶ SecurityMonitor ──✅
```

### 6.3 TARA: numpy вне ДВБ

Путь атаки (из docs/tara_abu.md): компрометация цепочки поставки numpy → выполнение в контексте контроллера → искажение логики принятия решений.

**Контрмера в решении:** numpy вынесена из ДВБ в `other/numpy_workflow.py`. Результат вычислений numpy передаётся как параметр в ДВБ, а не вызывается внутри критичного контура. ДВБ не зависит от numpy.

---

## Примечания

- Решение не модифицирует тесты заготовки (`src_starting_point/tests/`)
- Все новые тесты безопасности используют маркер `@pytest.mark.security`
- Код в `src_solution/` проходит проверку flake8 (0 замечаний)
- Покрытие ДВБ (`src_solution.abu.tcb`) составляет ≥80% благодаря полному набору тестов
