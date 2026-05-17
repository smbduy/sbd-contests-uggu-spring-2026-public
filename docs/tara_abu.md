# TARA (упрощённо): угрозы для АБУ

См. [context.md](context.md), раздел про TARA и компрометацию numpy.

## Диаграммы (TARA / ISO/SAE 21434, упрощённо)

1. **Путь атаки** (supply chain / numpy → критичные команды): [diagrams/tara_attack_numpy.puml](diagrams/tara_attack_numpy.puml) → [diagrams/png/tara_attack_numpy.png](diagrams/png/tara_attack_numpy.png).
2. **Обзор актив — угроз — мер** (фрагмент цикла ISO/SAE 21434): [diagrams/tara_iso21434_overview.puml](diagrams/tara_iso21434_overview.puml) → [diagrams/png/tara_iso21434_overview.png](diagrams/png/tara_iso21434_overview.png).

Сборка: `make diagrams` (нужен PlantUML).

## Кратко

- **Актив:** целостность критичных команд и режимов бурения (**SG_ADS_Authorized_critical_commands**).
- **Угроза:** компрометация цепочки поставки или библиотеки **numpy**, используемой в ДВБ.
- **Путь:** вредоносный артефакт в зависимостях → выполнение в контексте контроллера → искажение логики принятия решений.
- **Ущерб (damage):** несанкционированные команды, обход ограничений безопасности, аварийные режимы на объекте.

Конкурсанты ужесточают модель (разделение ДВБ, проверки целостности, сокращение доверенной базы).
