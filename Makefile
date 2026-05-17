# Все команды Python — через Pipenv (pipenv run), без системного pip.
PIPENV ?= pipenv
export PIPENV_VENV_IN_PROJECT=1

.PHONY: install tests-all diagrams prepare-cert-bundle certify-abu certify-abu-solution evaluate-score \
        evaluate-shard-plan evaluate-shard evaluate-distributed-aggregate \
        evaluate-distributed-local docker-build docker-up docker-down

# Установка зависимостей из Pipfile (виртуальное окружение в .venv/)
install:
        $(PIPENV) install --dev

tests-all: install
        $(PIPENV) run pytest -q src_starting_point/tests tests

diagrams:
        JAVA_TOOL_OPTIONS=-Djava.awt.headless=true plantuml -tpng -o png docs/diagrams/context.puml docs/diagrams/sequence_mission.puml docs/diagrams/certification_pipeline.puml docs/diagrams/abu_v1_internal.puml docs/diagrams/tara_attack_numpy.puml docs/diagrams/tara_iso21434_overview.puml

# Оценка по 22 критериям (см. docs/contest_regulations.md, docs/criteria_rubric.md); raw до 66, итог 10–20.
evaluate-score: install
        $(PIPENV) run python scripts/evaluate_contest_score.py

prepare-cert-bundle:
        bash scripts/prepare_certification_bundle.sh

certify-abu: install prepare-cert-bundle
        $(PIPENV) run python scripts/run_certification.py

# Алиас для обязательной команды самопроверки
certify-abu-solution: certify-abu

# Распределённая оценка: шардинг по решениям
evaluate-shard-plan: install
        $(PIPENV) run python scripts/evaluate_all_participant_repos.py --write-shard-plan

evaluate-shard: install
        $(PIPENV) run python scripts/evaluate_all_participant_repos.py --shard-plan evaluation/report/runs/$(RUN_ID)/shard_plan.json --shard-index $(SHARD_INDEX) --shards $(SHARDS)

evaluate-distributed-aggregate: install
        $(PIPENV) run python scripts/evaluate_all_participant_repos.py --aggregate --run-id final

evaluate-distributed-local: evaluate-score
        $(PIPENV) run python scripts/evaluate_all_participant_repos.py --local

docker-build:
        bash scripts/docker_build.sh

docker-up:
        bash scripts/docker_up.sh

docker-down:
        bash scripts/docker_down.sh
