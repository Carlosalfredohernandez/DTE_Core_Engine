"""
DTE Core Engine — Punto de entrada principal FastAPI.
"""

from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.api.v1.router import api_router
from app.config import get_settings
from app.infrastructure.logging_config import setup_logging
from app.infrastructure.database import engine
from app.domain.models import Base

logger = structlog.get_logger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Eventos de inicio y fin de la aplicación."""
    setup_logging()
    
    # Al iniciar: crea las tablas si no existen
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        
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


@app.get("/health")
async def health_check():
    return {
        "status": "ok",
        "ambiente": settings.sii_ambiente,
        "emisor": settings.rut_emisor,
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
