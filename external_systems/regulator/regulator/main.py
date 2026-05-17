"""REST API Регулятора (сертификация пакетов АБУ)."""

from __future__ import annotations

import json
import os
import shutil
import tarfile
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

from regulator.cost_model import (
    apply_heavy_dep_multiplier,
    total_estimated_cost,
)
from regulator.hash_util import sha256_file
from regulator.sandbox import PytestCovResult, run_pytest_with_coverage, run_security_tests_coverage
from regulator.sbom_parse import count_sbom_metrics
from regulator.sga_validate import load_sga, sga_document_for_response

app = FastAPI(title="Регулятор (прототип)", version="0.1.0")

# Память: сертификат -> метаданные
_certificates: dict[str, dict] = {}
_jobs: dict[str, dict] = {}


class CertificationRequestIn(BaseModel):
    """Заявка на сертификацию."""

    bundle_path: str = Field(description="Абсолютный путь к abu_certification_bundle.tar.gz")
    developer_company: str = Field(
        default="",
        description="Название компании-разработчика",
    )
    firmware_label: str = Field(
        default="",
        description="Метка или название прошивки (если пусто — из manifest.json пакета)",
    )


class CertificationResultOut(BaseModel):
    """Результат обработки заявки."""

    success: bool
    estimated_cost: float
    certificate_id: str | None = Field(
        default=None,
        description="SHA-256 архива при успехе",
    )
    coverage_percent: float = 0.0
    security_coverage_percent: float = 0.0
    coverage_tcb_percent: float = 0.0
    message: str = ""
    developer_company: str = ""
    firmware_label: str = ""
    tcb_lines_of_code: int = Field(
        default=0,
        description="Число строк *.py в пакете abu (ДВБ), учтённое в стоимости",
    )
    tcb_cyclomatic_sum: int = Field(
        default=0,
        description="Сумма цикломатических сложностей функций/методов abu (ДВБ)",
    )


class CertificationSummaryRow(BaseModel):
    """Строка сводной таблицы сертифицированных прошивок."""

    certificate_id: str
    developer_company: str
    firmware_label: str
    estimated_cost: float
    coverage_percent: float
    certified_at: str


class SgaOut(BaseModel):
    """SGA (security goals and assumptions) по сертификату."""

    certificate_id: str
    security_goals: list
    security_assumptions: list


def _repo_root() -> Path:
    """Корень репозитория (для тестов)."""
    return Path(__file__).resolve().parents[3]


def _unpack_cov_result(result: tuple | PytestCovResult) -> tuple[bool, float, str, float]:
    """Распаковывает результат run_pytest_with_coverage в (ok, cov_total, log, cov_tcb).

    Поддерживает как кортеж (ok, cov_pct, log), так и PytestCovResult.
    """
    if isinstance(result, PytestCovResult):
        return result.ok, result.coverage_total, result.log, result.coverage_tcb
    ok, cov_pct, log = result
    return ok, cov_pct, log, 0.0


def process_certification(
    bundle_path: Path,
    *,
    developer_company: str = "",
    firmware_label: str = "",
) -> CertificationResultOut:
    """
    Полный цикл: хэш, SGA, SBOM_TCB/SBOM_OTHER, стоимость (SBOM + LOC/цикломатика abu), песочница pytest + security.

    :param bundle_path: путь к .tar.gz
    """
    if not bundle_path.is_file():
        return CertificationResultOut(
            success=False,
            estimated_cost=0.0,
            message="файл пакета не найден",
            developer_company=developer_company,
            firmware_label=firmware_label,
        )

    cert_hash = sha256_file(bundle_path)
    tmp = Path(tempfile.mkdtemp(prefix="cert_extract_"))
    try:
        with tarfile.open(bundle_path, "r:gz") as tf:
            tf.extractall(tmp)

        bundle_root = tmp / "cert_bundle"
        sga_path = bundle_root / "security" / "sga.json"
        sbom_tcb = bundle_root / "sbom" / "SBOM_TCB.cdx.json"
        sbom_other = bundle_root / "sbom" / "SBOM_OTHER.cdx.json"
        manifest_path = bundle_root / "manifest.json"
        source_dir = bundle_root / "source"

        ok_sga, sga_data, sga_msg = load_sga(sga_path)
        if not ok_sga or sga_data is None:
            return CertificationResultOut(
                success=False,
                estimated_cost=0.0,
                message=sga_msg,
                developer_company=developer_company,
                firmware_label=firmware_label,
            )

        if not sbom_tcb.is_file() or not sbom_other.is_file():
            return CertificationResultOut(
                success=False,
                estimated_cost=0.0,
                message="в пакете должны быть sbom/SBOM_TCB.cdx.json и sbom/SBOM_OTHER.cdx.json",
                developer_company=developer_company,
                firmware_label=firmware_label,
            )

        n_tcb, e_tcb = count_sbom_metrics(sbom_tcb)
        n_other, e_other = count_sbom_metrics(sbom_other)
        tcb_loc, tcb_cc = 0, 0
        if source_dir.is_dir():
            abu_pkg = source_dir / "abu"
            if abu_pkg.is_dir():
                from regulator.tcb_metrics import compute_tcb_source_metrics

                tcb_loc, tcb_cc = compute_tcb_source_metrics(abu_pkg)
        ipc_u = ipc_t = 0
        if manifest_path.is_file():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            ipc_u = max(0, int(manifest.get("domain_ipc_untrusted_boundary_edges", 0)))
            ipc_t = max(0, int(manifest.get("domain_ipc_trusted_boundary_edges", 0)))
        cost = total_estimated_cost(
            n_tcb,
            e_tcb,
            n_other,
            e_other,
            tcb_loc=tcb_loc,
            tcb_cyclomatic_sum=tcb_cc,
            ipc_untrusted_boundary_edges=ipc_u,
            ipc_trusted_boundary_edges=ipc_t,
        )
        req_path = source_dir / "requirements.txt"
        cost = apply_heavy_dep_multiplier(cost, sbom_tcb, req_path)

        if not source_dir.is_dir():
            return CertificationResultOut(
                success=False,
                estimated_cost=cost,
                message="в пакете нет source/",
                developer_company=developer_company,
                firmware_label=firmware_label,
                tcb_lines_of_code=tcb_loc,
                tcb_cyclomatic_sum=tcb_cc,
            )

        if not manifest_path.is_file():
            manifest = {}
        fw_label = firmware_label.strip() or str(manifest.get("package_name", ""))
        tests_root = manifest.get("tests_root", "tests")
        fail_under = float(os.environ.get("REGULATOR_COV_FAIL_UNDER", "80"))

        ignore_sec: list[str] = []
        if (source_dir / tests_root / "security").is_dir():
            ignore_sec = [f"--ignore={tests_root}/security"]

        ok, cov_pct, log, cov_tcb = _unpack_cov_result(
            run_pytest_with_coverage(
                source_dir,
                tests_subdir=tests_root,
                cov_package="abu",
                fail_under=fail_under,
                extra_pytest_args=ignore_sec or None,
            )
        )

        if not ok:
            return CertificationResultOut(
                success=False,
                estimated_cost=cost,
                certificate_id=None,
                coverage_percent=cov_pct,
                coverage_tcb_percent=cov_tcb,
                message=log[-2000:] if log else "pytest failed",
                developer_company=developer_company,
                firmware_label=fw_label,
                tcb_lines_of_code=tcb_loc,
                tcb_cyclomatic_sum=tcb_cc,
            )

        # Проверка порога покрытия ДВБ (REGULATOR_TCB_COV_REQUIRED)
        tcb_cov_required = float(
            os.environ.get("REGULATOR_TCB_COV_REQUIRED", "0")
        )
        if tcb_cov_required > 0 and cov_tcb < tcb_cov_required:
            return CertificationResultOut(
                success=False,
                estimated_cost=cost,
                certificate_id=None,
                coverage_percent=cov_pct,
                coverage_tcb_percent=cov_tcb,
                message=(
                    f"покрытие ДВБ {cov_tcb:.1f}% ниже требуемого "
                    f"{tcb_cov_required:.1f}%"
                ),
                developer_company=developer_company,
                firmware_label=fw_label,
                tcb_lines_of_code=tcb_loc,
                tcb_cyclomatic_sum=tcb_cc,
            )

        sec_ok, sec_cov, sec_log = run_security_tests_coverage(source_dir)
        if not sec_ok:
            return CertificationResultOut(
                success=False,
                estimated_cost=cost,
                certificate_id=None,
                coverage_percent=cov_pct,
                security_coverage_percent=sec_cov,
                message=(sec_log[-1500:] if sec_log else "security pytest failed"),
                developer_company=developer_company,
                firmware_label=fw_label,
                tcb_lines_of_code=tcb_loc,
                tcb_cyclomatic_sum=tcb_cc,
            )

        certified_at = datetime.now(timezone.utc).isoformat()
        sga_snapshot = sga_document_for_response(sga_data)
        _certificates[cert_hash] = {
            "valid": True,
            "estimated_cost": cost,
            "coverage_percent": cov_pct,
            "security_coverage_percent": sec_cov,
            "developer_company": developer_company.strip(),
            "firmware_label": fw_label,
            "certified_at": certified_at,
            "sga": sga_snapshot,
            "tcb_lines_of_code": tcb_loc,
            "tcb_cyclomatic_sum": tcb_cc,
        }
        return CertificationResultOut(
            success=True,
            estimated_cost=cost,
            certificate_id=cert_hash,
            coverage_percent=cov_pct,
            security_coverage_percent=sec_cov,
            message="ok",
            developer_company=developer_company.strip(),
            firmware_label=fw_label,
            tcb_lines_of_code=tcb_loc,
            tcb_cyclomatic_sum=tcb_cc,
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@app.get("/api/v1/health")
def health() -> dict[str, str]:
    """Проверка работоспособности."""
    return {"status": "ok", "service": "regulator"}


@app.post("/api/v1/certification/requests", response_model=CertificationResultOut)
def submit_certification(body: CertificationRequestIn) -> CertificationResultOut:
    """Принять заявку и выполнить сертификацию (синхронно), путь к архиву на диске сервера."""
    try:
        path = Path(body.bundle_path).resolve()
        return process_certification(
            path,
            developer_company=body.developer_company,
            firmware_label=body.firmware_label,
        )
    except OSError as exc:
        return CertificationResultOut(
            success=False,
            estimated_cost=0.0,
            message=str(exc),
            developer_company=body.developer_company,
            firmware_label=body.firmware_label,
        )


@app.post("/api/v1/certification/upload", response_model=CertificationResultOut)
async def upload_certification(
    bundle: UploadFile = File(..., description="Архив abu_certification_bundle.tar.gz"),
    developer_company: str = Form("", description="Название компании-разработчика"),
    firmware_label: str = Form("", description="Метка прошивки"),
) -> CertificationResultOut:
    """Загрузить сертификационный пакет телом запроса и вернуть результат сертификации."""
    data = await bundle.read()
    if not data:
        raise HTTPException(status_code=400, detail="пустой файл")
    if not data.startswith(b"\x1f\x8b"):
        raise HTTPException(
            status_code=400,
            detail="ожидается gzip-сжатый архив (.tar.gz)",
        )

    tmp_dir = Path(tempfile.mkdtemp(prefix="upload_bundle_"))
    tmp_path = tmp_dir / "abu_certification_bundle.tar.gz"
    try:
        tmp_path.write_bytes(data)
        return process_certification(
            tmp_path,
            developer_company=developer_company,
            firmware_label=firmware_label,
        )
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@app.get("/api/v1/certification/summary", response_model=list[CertificationSummaryRow])
def certification_summary() -> list[CertificationSummaryRow]:
    """Сводная таблица сертифицированных прошивок, разработчиков и стоимости."""
    rows: list[CertificationSummaryRow] = []
    for cert_id, row in _certificates.items():
        if not row.get("valid"):
            continue
        rows.append(
            CertificationSummaryRow(
                certificate_id=cert_id,
                developer_company=str(row.get("developer_company", "")),
                firmware_label=str(row.get("firmware_label", "")),
                estimated_cost=float(row.get("estimated_cost", 0.0)),
                coverage_percent=float(row.get("coverage_percent", 0.0)),
                certified_at=str(row.get("certified_at", "")),
            )
        )
    return rows


@app.get("/api/v1/certificates/{certificate_id}/sga", response_model=SgaOut)
def get_sga(certificate_id: str) -> SgaOut:
    """Выдача SGA (целей и предположений безопасности) по сертификату."""
    row = _certificates.get(certificate_id)
    if not row or not row.get("valid"):
        raise HTTPException(status_code=404, detail="сертификат не найден")
    sga = row.get("sga") or {}
    return SgaOut(
        certificate_id=certificate_id,
        security_goals=list(sga.get("security_goals", [])),
        security_assumptions=list(sga.get("security_assumptions", [])),
    )


@app.get("/api/v1/certificates/{certificate_id}")
def get_certificate(certificate_id: str) -> dict:
    """Проверка действительности сертификата (хэш пакета)."""
    if certificate_id in _certificates:
        row = _certificates[certificate_id]
        return {
            "valid": True,
            "certificate_id": certificate_id,
            "estimated_cost": row.get("estimated_cost"),
            "developer_company": row.get("developer_company"),
            "firmware_label": row.get("firmware_label"),
            "security_coverage_percent": row.get("security_coverage_percent"),
            "has_sga": bool(row.get("sga")),
            "tcb_lines_of_code": row.get("tcb_lines_of_code"),
            "tcb_cyclomatic_sum": row.get("tcb_cyclomatic_sum"),
        }
    return {"valid": False, "certificate_id": certificate_id}


@app.post("/api/v1/certification/requests/async", response_model=dict)
def submit_async(body: CertificationRequestIn) -> dict:
    """Заглушка асинхронной заявки: возвращает job_id (тот же синхронный путь в прототипе)."""
    jid = str(uuid.uuid4())
    path = Path(body.bundle_path).resolve()
    result = process_certification(
        path,
        developer_company=body.developer_company,
        firmware_label=body.firmware_label,
    )
    _jobs[jid] = result.model_dump()
    return {"job_id": jid, "result": result.model_dump()}
