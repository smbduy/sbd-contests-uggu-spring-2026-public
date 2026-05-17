# SBOM для ДВБ (SBOM_TCB) и некритичного кода (SBOM_OTHER)

В сертификационном пакете АБУ Регулятор ожидает **два** файла CycloneDX 1.5:

| Файл в пакете | Смысл |
|---------------|--------|
| `sbom/SBOM_TCB.cdx.json` | Компоненты **доверенной вычислительной базы (ДВБ)** — код и библиотеки, компрометация которых **критична** для целей безопасности (SG) из SGA. |
| `sbom/SBOM_OTHER.cdx.json` | Остальные зависимости (например HTTP-стек), если вы **явно** выносите их из ДВБ и обосновываете в архитектуре. |

Без согласованного разделения вся поставка может считаться ДВБ при анализе рисков; разделение должно быть согласовано с **SGA**, тестами безопасности и фактическим кодом.

## Что делает Регулятор с SBOM

Из каждого JSON извлекаются:

- **N** — число элементов в `components`;
- **C** — число рёбер: сумма длин списков `dependsOn` в массиве `dependencies`.

Стоимость сертификации: полная полиномиальная оценка по **SBOM_TCB**, плюс вклад **SBOM_OTHER**, делённый на **100** (см. `SBOM_OTHER_COST_DIVISOR` в коде Регулятора). Если в **SBOM_TCB** или в `requirements.txt` поставки указаны «тяжёлые» зависимости ДВБ (например **numpy**), к базовой сумме применяется **множитель ×2**.

Подробнее о пакете: [certification_process.md](certification_process.md).

## Минимальный формат CycloneDX (прототип)

Обязательно для совместимости с парсером:

- `bomFormat`: `"CycloneDX"`, `specVersion`: `"1.5"`;
- `metadata.component` — корневой компонент BOM;
- у каждого элемента в `components` уникальный `bom-ref`;
- `dependencies`: для каждого `ref`, фигурирующего в графе, блок `{ "ref": "...", "dependsOn": [ ... ] }` (может быть пустым).

Имена пакетов в примерах: `pkg:pypi/<name>@<version>` для библиотек PyPI.

## Практические шаги для конкурсантов

1. Зафиксировать **цели безопасности** и границу ДВБ (см. [context.md](context.md), [tara_abu.md](tara_abu.md)).
2. Составить инвентаризацию: `requirements.txt`, модули исходников, что исполняется в контуре критичных решений.
3. Решить, что попадает в **TCB** (SBOM_TCB), что остаётся в **OTHER** — и почему это не нарушает SG при модели угроз.
4. Заполнить манифест [sbom_manifest.json](sbom_manifest.json) (скопировать в свой каталог или править в репозитории).
5. Сгенерировать CycloneDX: `pipenv run python scripts/generate_sbom_cdx.py` — по умолчанию перезаписывает [examples/SBOM_TCB.cdx.json](examples/SBOM_TCB.cdx.json) и [examples/SBOM_OTHER.cdx.json](examples/SBOM_OTHER.cdx.json).
6. Проверить согласованность с реальной поставкой и при необходимости повторить сертификацию (`make prepare-cert-bundle`, `make certify-abu`).

**Важно:** манифест в репозитории — **модель заготовки**. Участники обязаны согласовать SBOM с фактическими зависимостями и архитектурой; иначе SBOM не будет отражать реальную поверхность атаки.

Для **оценки решения** (критерий **C14**) в каталоге решения используются два файла CycloneDX: `src_solution/sbom/SBOM_TCB.cdx.json` и `src_solution/sbom/SBOM_OTHER.cdx.json` — декларация, в том числе положения **numpy** относительно ДВБ (см. [contest_regulations.md](contest_regulations.md)).

## Скрипт и примеры

- Манифест: [sbom_manifest.json](sbom_manifest.json)
- Генератор: [../scripts/generate_sbom_cdx.py](../scripts/generate_sbom_cdx.py) (вызывается из [../scripts/prepare_certification_bundle.sh](../scripts/prepare_certification_bundle.sh) перед сборкой архива)
