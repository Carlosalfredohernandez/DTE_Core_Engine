"""
DTE Core Engine — Punto de entrada principal FastAPI.
"""

from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import inspect, text

from app.api.v1.router import api_router
from app.config import get_settings
from app.infrastructure.logging_config import setup_logging
from app.infrastructure.database import async_session_factory, engine
from app.domain.models import Base
from app.services.empresa_service import seed_default_empresa_data

logger = structlog.get_logger(__name__)
settings = get_settings()
ALEMBIC_HEAD_REVISION = "1b0e3f7c9a21"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Eventos de inicio y fin de la aplicación."""
    setup_logging()
    
    # Al iniciar: crea las tablas si no existen
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with async_session_factory() as session:
        await seed_default_empresa_data(session)
        
    logger.info(
        "Iniciando Motor DTE",
        ambiente=settings.sii_ambiente,
        db_url=settings.database_url.split("@")[-1], # Log sin credenciales
    )
    yield
    logger.info("Motor DTE apagándose")


app = FastAPI(
    title="Motor DTE SII",
    description="API REST para emisión de Boletas Electrónicas en el SII",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/api/v1/dashboard", status_code=302)


@app.get("/health")
async def health_check():
    return {
        "status": "ok",
        "ambiente": settings.sii_ambiente,
        "emisor": settings.rut_emisor,
    }


@app.get("/health/schema")
async def health_schema():
    """Verifica si el esquema multiempresa ya existe en la base de datos."""
    expected_tables = ["empresas", "cafs", "dtes", "sii_log"]
    expected_columns = {
        "empresas": [
            "id",
            "rut_emisor",
            "rut_envia",
            "razon_social_emisor",
            "giro_emisor",
            "acteco_emisor",
            "dir_origen",
            "cmna_origen",
            "ciudad_origen",
            "sii_ambiente",
            "sii_fecha_resolucion",
            "sii_numero_resolucion",
            "brand_name",
            "brand_logo_url",
            "brand_accent_1",
            "brand_accent_2",
            "api_key",
            "cert_pfx_path",
            "cert_pfx_base64",
            "cert_pfx_password",
            "es_default",
            "activo",
            "fecha_creacion",
            "fecha_actualizacion",
        ],
        "cafs": ["empresa_id"],
        "dtes": ["empresa_id"],
        "sii_log": ["empresa_id"],
    }

    async with engine.connect() as conn:
        schema_info = await conn.run_sync(
            lambda sync_conn: _build_schema_health(sync_conn, expected_tables, expected_columns)
        )

    return schema_info


@app.get("/health/railway")
async def health_railway():
    """Chequeo temporal de readiness para Railway y ambiente multiempresa."""
    base_health: dict[str, object] = {
        "status": "ok",
        "environment": str(settings.sii_ambiente),
        "database_url_present": bool(settings.database_url),
    }

    try:
        async with engine.connect() as conn:
            ping = await conn.run_sync(lambda sync_conn: sync_conn.exec_driver_sql("SELECT 1").scalar_one())
            schema_info = await conn.run_sync(
                lambda sync_conn: _build_schema_health(sync_conn, ["empresas", "cafs", "dtes", "sii_log"], {
                    "empresas": [
                        "id",
                        "rut_emisor",
                        "rut_envia",
                        "razon_social_emisor",
                        "giro_emisor",
                        "acteco_emisor",
                        "dir_origen",
                        "cmna_origen",
                        "ciudad_origen",
                        "sii_ambiente",
                        "sii_fecha_resolucion",
                        "sii_numero_resolucion",
                        "brand_name",
                        "brand_logo_url",
                        "brand_accent_1",
                        "brand_accent_2",
                        "api_key",
                        "cert_pfx_path",
                        "cert_pfx_base64",
                        "cert_pfx_password",
                        "es_default",
                        "activo",
                        "fecha_creacion",
                        "fecha_actualizacion",
                    ],
                    "cafs": ["empresa_id"],
                    "dtes": ["empresa_id"],
                    "sii_log": ["empresa_id"],
                })
            )
    except Exception as exc:
        return {
            "status": "degraded",
            "ready_to_deploy": False,
            "database_ok": False,
            "error": str(exc),
            "recommendation": "Revisar DATABASE_URL, aplicar migraciones Alembic y verificar la tabla empresas.",
        }

    ready_to_deploy = bool(
        ping == 1
        and schema_info.get("multiempresa_ready")
        and schema_info.get("alembic", {}).get("up_to_date")
    )

    base_health.update(
        {
            "database_ok": True,
            "schema": schema_info,
            "ready_to_deploy": ready_to_deploy,
            "recommendation": (
                "Listo para Railway" if ready_to_deploy else "Faltan migraciones o el esquema multiempresa está incompleto"
            ),
        }
    )
    return base_health


def _build_schema_health(sync_conn, expected_tables: list[str], expected_columns: dict[str, list[str]]) -> dict[str, object]:
    inspector = inspect(sync_conn)
    tables = set(inspector.get_table_names())
    alembic_version_exists = "alembic_version" in tables
    alembic_revisions: list[str] = []
    if alembic_version_exists:
        try:
            rows = sync_conn.execute(text("SELECT version_num FROM alembic_version")).fetchall()
            alembic_revisions = [str(row[0]) for row in rows if row and row[0]]
        except Exception:
            alembic_revisions = []

    table_details: dict[str, dict[str, object]] = {}
    for table in expected_tables:
        exists = table in tables
        columns = [column["name"] for column in inspector.get_columns(table)] if exists else []
        missing_columns = [column for column in expected_columns.get(table, []) if column not in columns]
        table_details[table] = {
            "exists": exists,
            "columns": columns,
            "missing_columns": missing_columns,
        }

    missing_tables = [table for table in expected_tables if table not in tables]
    all_ok = not missing_tables and all(not details["missing_columns"] for details in table_details.values())
    alembic_state = {
        "exists": alembic_version_exists,
        "versions": alembic_revisions,
        "head_revision": ALEMBIC_HEAD_REVISION,
        "up_to_date": alembic_version_exists and ALEMBIC_HEAD_REVISION in alembic_revisions,
        "migrated": alembic_version_exists,
    }

    return {
        "status": "ok" if all_ok else "degraded",
        "multiempresa_ready": all_ok,
        "alembic": alembic_state,
        "missing_tables": missing_tables,
        "tables": table_details,
    }

@app.get("/debug/env")
async def debug_env():
    """Ruta secreta temporal para leer la memoria del SO de Railway."""
    import os
    keys = list(os.environ.keys())
    base64_exists = any("CERT_PFX_BASE" in k for k in keys)
    base64_value = next((v for k, v in os.environ.items() if "CERT_PFX_BASE" in k), "")
    return {
        "railway_vars_count": len(keys),
        "detecto_la_variable": base64_exists,
        "longitud_del_texto": len(base64_value),
        "lista_de_variables": keys
    }

app.include_router(api_router, prefix="/api/v1")


# Exception Handlers Globales
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Error no manejado", error=str(exc), path=request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "Error interno del servidor", "code": "INTERNAL_ERROR"},
    )
