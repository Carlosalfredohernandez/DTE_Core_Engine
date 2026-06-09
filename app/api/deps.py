"""
DTE Core Engine — Dependencias para FastAPI.
"""

from typing import Annotated

from fastapi import Depends, HTTPException, Security, status, Header
from fastapi.security import APIKeyHeader
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.domain.models import Empresa
from app.infrastructure.database import get_db_session
from app.services.empresa_service import ensure_default_empresa, resolve_empresa_by_api_key

settings = get_settings()

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def get_api_key(
    api_key: str = Security(api_key_header),
    db: AsyncSession = Depends(get_db_session),
) -> str:
    """Valida una API Key global o registrada por empresa."""
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key inválida o faltante",
        )

    if api_key == settings.api_key:
        return api_key

    empresa = await resolve_empresa_by_api_key(db, api_key)
    if empresa is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key inválida o faltante",
        )

    return api_key


async def get_current_empresa(
    api_key: str = Security(api_key_header),
    db: AsyncSession = Depends(get_db_session),
) -> Empresa:
    """Resuelve la empresa activa a partir de la API Key."""
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key inválida o faltante",
        )

    # If caller used the global/admin API key, allow optionally targeting a
    # specific empresa by sending the `X-Empresa-Id` header. This override is
    # only honored when the global API key is used (admin scenario).
    empresa_id_header: int | None = Header(None, alias="X-Empresa-Id")

    if api_key == settings.api_key:
        if empresa_id_header is not None:
            empresa = await db.get(Empresa, empresa_id_header)
            if empresa is None or not empresa.activo:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Empresa no encontrada o inactiva",
                )
            return empresa
        return await ensure_default_empresa(db)

    empresa = await resolve_empresa_by_api_key(db, api_key)
    if empresa is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key inválida o faltante",
        )
    return empresa

# Alias para usar en endpoints:
# db: AsyncSession = Depends(get_db)
# _: str = Depends(get_api_key)
