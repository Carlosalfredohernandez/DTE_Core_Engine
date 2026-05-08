"""
DTE Core Engine — Dependencias para FastAPI.
"""

from typing import Annotated

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.infrastructure.database import get_db_session

settings = get_settings()

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def get_api_key(api_key: str = Security(api_key_header)) -> str:
    """Valida la API Key estática."""
    if not api_key or api_key != settings.api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key inválida o faltante",
        )
    return api_key

# Alias para usar en endpoints:
# db: AsyncSession = Depends(get_db)
# _: str = Depends(get_api_key)
