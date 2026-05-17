# Тесты безопасности АБУ и цели (ЦБ)

| Цель (SG) | Файлы тестов | Комментарий |
|-----------|----------------|-------------|
| SG_ADS_Authorized_critical_commands | [src_starting_point/tests/security/test_sg_authorized_commands.py](../src_starting_point/tests/security/test_sg_authorized_commands.py) | Лимиты глубины/оборотов, доступ к миссии через API |
| SG_ADS_Controlled_operations | [src_starting_point/tests/security/test_sg_controlled_ops.py](../src_starting_point/tests/security/test_sg_controlled_ops.py) | Риск, аварийный стоп, аномалия |
| SG_ADS_Security_events_store | [src_starting_point/tests/security/test_sg_security_events.py](../src_starting_point/tests/security/test_sg_security_events.py), test_event_log | Журнал, numpy в ДВБ |
| Интеграция сценария | [src_starting_point/tests/security/test_app_mission_flow.py](../src_starting_point/tests/security/test_app_mission_flow.py) | Миссия, tick, кольцо событий |

Регулятор в песочнице выполняет общие тесты (без `tests/security` в первом прогоне) и отдельно **тесты безопасности** с порогом покрытия `REGULATOR_SECURITY_COV_FAIL_UNDER` (по умолчанию 70%).

Участник конкурса дополняет соответствие тестов и ЦБ для кода в `src_solution/` (см. отчёт `docs/solution.md`).
