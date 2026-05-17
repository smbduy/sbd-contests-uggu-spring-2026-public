# Тесты безопасности АБУ и цели (ЦБ)

## Заготовка (src_starting_point)

| Цель (SG) | Файлы тестов | Проверяемые файлы | Комментарий |
|-----------|----------------|-------------------|-------------|
| SG_ADS_Authorized_critical_commands | `src_starting_point/tests/security/test_sg_authorized_commands.py` | `src_starting_point/abu/safety.py` | Лимиты глубины/оборотов, доступ к миссии через API |
| SG_ADS_Controlled_operations | `src_starting_point/tests/security/test_sg_controlled_ops.py` | `src_starting_point/abu/safety.py`, `src_starting_point/abu/pseudo_ai.py` | Риск, аварийный стоп, аномалия |
| SG_ADS_Security_events_store | `src_starting_point/tests/security/test_sg_security_events.py`, `src_starting_point/tests/test_event_log.py` | `src_starting_point/abu/event_log.py` | Журнал, numpy в ДВБ |
| Интеграция сценария | `src_starting_point/tests/security/test_app_mission_flow.py` | `src_starting_point/abu/app.py` | Миссия, tick, кольцо событий |

## Решение (src_solution)

| Цель (SG) | Файлы тестов | Проверяемые файлы в `src_solution/` | Комментарий |
|-----------|----------------|-------------------------------------|-------------|
| SG_ADS_Authorized_critical_commands | `src_solution/tests/security/test_sg_authorized_commands.py` | `src_solution/abu/tcb/safety.py` | enforce_depth_cap, enforce_rpm_cap — без зависимости от pseudo_ai |
| SG_ADS_Controlled_operations | `src_solution/tests/security/test_sg_controlled_ops.py` | `src_solution/abu/tcb/safety.py` | should_emergency_stop, check_safety_constraints — параметры от ИИ, решение в ДВБ |
| SG_ADS_Security_events_store | `src_solution/tests/security/test_sg_security_events.py` | `src_solution/abu/tcb/event_log.py` | Кольцевой буфер, полный журнал, потокобезопасность |
| Монитор безопасности и политики | `src_solution/tests/security/test_sg_monitor_policies.py` | `src_solution/abu/tcb/security_monitor.py`, `src_solution/abu/tcb/route_monitor.py`, `src_solution/abu/tcb/domain_guard.py`, `src_solution/abu/tcb/parameter_guard.py` | Default deny, whitelist, egress/ingress, валидация параметров |
| Импорт + event_log | `tests/test_solution_event_log.py` | `src_solution/abu/tcb/event_log.py` | Запись, чтение, свойства, пустой журнал |
| Импорт + safety | `tests/test_solution_safety.py` | `src_solution/abu/tcb/safety.py` | Лимиты, аварийный стоп, комплексная проверка |
| Монитор + policies | `tests/test_solution_monitor.py` | `src_solution/abu/tcb/security_monitor.py`, `src_solution/abu/tcb/route_monitor.py` | Default deny, whitelist, интеграция |
| Домены и изоляция | `tests/test_solution_domains.py` | `src_solution/abu/tcb/domain_guard.py`, `src_solution/abu/tcb/parameter_guard.py` | egress/ingress, валидация, request/response |

Регулятор в песочнице выполняет общие тесты (без `tests/security` в первом прогоне) и отдельно **тесты безопасности** с порогом покрытия `REGULATOR_SECURITY_COV_FAIL_UNDER` (по умолчанию 70%).
